import json
import socket
import threading
import time
import select
import os
import sys
import struct
import logging
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from common import TunnelCrypto, generate_config_wizard, PROTO_TCP, PROTO_UDP

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class TunnelHandler(BaseHTTPRequestHandler):
    crypto = None
    max_post_bytes = 5242880
    timeout = 30
    udp_timeout = 60
    sessions = {}
    sessions_lock = threading.Lock()
    executor = ThreadPoolExecutor(max_workers=50)
    
    def do_POST(self):
        client = self.client_address[0]
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            logger.debug(f"[{client}] POST request: {content_length} bytes")
            
            if content_length > self.max_post_bytes:
                logger.error(f"[{client}] Payload too large: {content_length} > {self.max_post_bytes}")
                self.send_error(413, "Payload too large")
                return
            
            body = self.rfile.read(content_length).decode()
            
            try:
                plain = self.crypto.decrypt(body)
                logger.debug(f"[{client}] Decrypted: {len(plain)} bytes")
            except Exception as e:
                logger.error(f"[{client}] Decryption failed: {e}")
                self.send_error(400, "Decryption failed")
                return
            
            # Parse the message
            try:
                msg = json.loads(plain.decode())
                if isinstance(msg, dict) and msg.get("type") == "connect":
                    logger.info(f"[{client}] CONNECT request: {msg}")
                    self._handle_connect(msg)
                    return
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            
            # Handle session-prefixed messages
            if b'::' in plain:
                parts = plain.split(b'::', 1)
                session_id = parts[0].decode('ascii', errors='ignore')
                message = parts[1] if len(parts) > 1 else b""
                
                logger.debug(f"[{client}] Session {session_id}: {len(message)} bytes, type: {'UDP' if message.startswith(b'UDP:') else 'TCP'}")
                
                if session_id in self.sessions:
                    # Check if it's a UDP packet
                    if message.startswith(b"UDP:"):
                        self._handle_udp_data(client, session_id, message[4:])
                    else:
                        self._handle_tcp_data(client, session_id, message)
                else:
                    logger.warning(f"[{client}] Unknown session: {session_id}")
                    self._send_encrypted(b"invalid_session")
            else:
                logger.warning(f"[{client}] Invalid message format: {len(plain)} bytes")
                self._send_encrypted(b"invalid_format")
                
        except (BrokenPipeError, ConnectionResetError):
            logger.debug(f"[{client}] Client disconnected")
        except Exception as e:
            logger.error(f"[{client}] Error handling POST: {e}", exc_info=True)
            try:
                self.send_error(500)
            except:
                pass
    
    def _resolve_and_connect(self, host, port):
        """Resolve hostname and connect with detailed logging."""
        logger.info(f"Resolving {host}:{port}")
        
        # Check if it's an IPv6 address
        try:
            socket.inet_pton(socket.AF_INET6, host)
            logger.debug(f"{host} is IPv6, attempting direct connection")
            try:
                sock = socket.create_connection((host, port), timeout=10)
                logger.info(f"IPv6 connection successful to {host}:{port}")
                return sock
            except OSError as e:
                logger.error(f"IPv6 connection failed: {e}")
                raise
        except socket.error:
            pass
        
        # Try to resolve as hostname, prefer IPv4
        try:
            addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addrs.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
            
            logger.debug(f"Resolved {host} to {len(addrs)} addresses")
            
            for family, socktype, proto, canonname, sockaddr in addrs:
                try:
                    logger.debug(f"Trying {sockaddr}...")
                    sock = socket.socket(family, socktype, proto)
                    sock.settimeout(10)
                    sock.connect(sockaddr)
                    logger.info(f"Connected to {sockaddr}")
                    return sock
                except OSError as e:
                    logger.warning(f"Failed to connect to {sockaddr}: {e}")
                    continue
            
            raise OSError(f"Could not connect to any of {len(addrs)} addresses")
        except socket.gaierror as e:
            raise OSError(f"DNS resolution failed for {host}: {e}")
    
    def _handle_connect(self, msg):
        host = msg.get("host")
        port = msg.get("port")
        proto = msg.get("proto", PROTO_TCP)
        
        if not host or not port:
            logger.error("Missing host/port in connect message")
            resp = json.dumps({"status": "error", "reason": "Missing host/port"})
            self._send_encrypted(resp.encode())
            return
        
        try:
            session_id = self._generate_session_id()
            
            if proto == PROTO_UDP:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                logger.info(f"UDP session {session_id} created for {host}:{port}")
            else:
                logger.info(f"Creating TCP connection to {host}:{port}")
                sock = self._resolve_and_connect(host, port)
                sock.setblocking(False)
                logger.info(f"TCP session {session_id} created for {host}:{port}")
            
            with self.sessions_lock:
                self.sessions[session_id] = {
                    'socket': sock,
                    'last_active': time.time(),
                    'host': host,
                    'port': port,
                    'proto': proto,
                    'created': time.time(),
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'requests': 0
                }
            
            resp = json.dumps({"status": "ok", "session": session_id, "proto": proto})
            self._send_encrypted(resp.encode())
            
        except Exception as e:
            logger.error(f"Connection failed to {host}:{port}: {e}")
            resp = json.dumps({"status": "error", "reason": str(e)})
            self._send_encrypted(resp.encode())
    
    def _handle_tcp_data(self, client, session_id, message):
        """Handle TCP data messages with detailed logging."""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session or session['proto'] != PROTO_TCP:
                logger.warning(f"[{client}] Invalid TCP session: {session_id}")
                self._send_encrypted(b"invalid_session")
                return
            session['last_active'] = time.time()
            session['requests'] += 1
        
        sock = session['socket']
        
        # Handle control messages
        if message == b"CLOSE":
            logger.info(f"[{client}] Session {session_id} closed by client")
            logger.info(f"[{client}] Session stats: {session['requests']} requests, {session['bytes_sent']} sent, {session['bytes_received']} received")
            self._close_session(session_id)
            self._send_encrypted(b"closed")
            return
        
        # Forward data to destination
        if message and message != b"HEARTBEAT":
            try:
                sock.sendall(message)
                session['bytes_sent'] += len(message)
                logger.debug(f"[{client}] Session {session_id}: Sent {len(message)} bytes to destination")
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                logger.error(f"[{client}] Session {session_id}: Write error: {e}")
                self._close_session(session_id)
                self._send_encrypted(b"destination_closed")
                return
        else:
            logger.debug(f"[{client}] Session {session_id}: {'Heartbeat' if message == b'HEARTBEAT' else 'Empty message'}")
        
        # Read available data immediately
        response_data = b""
        try:
            while True:
                ready = select.select([sock], [], [], 0.001)
                if ready[0]:
                    chunk = sock.recv(65536)
                    if not chunk:
                        logger.info(f"[{client}] Session {session_id}: Destination closed connection")
                        self._close_session(session_id)
                        response_data = b"destination_closed"
                        break
                    response_data += chunk
                    session['bytes_received'] += len(chunk)
                    logger.debug(f"[{client}] Session {session_id}: Received {len(chunk)} bytes from destination")
                    if len(response_data) >= self.max_post_bytes - 2000:
                        break
                else:
                    break
        except (BlockingIOError, socket.error):
            pass
        except Exception as e:
            logger.error(f"[{client}] Session {session_id}: Read error: {e}")
            self._close_session(session_id)
            response_data = b"destination_closed"
        
        # Always respond immediately
        self._send_encrypted(response_data if response_data else b"")
        if response_data:
            logger.debug(f"[{client}] Session {session_id}: Sending {len(response_data)} bytes response")
    
    def _handle_udp_data(self, client, session_id, data):
        """Handle UDP data with detailed logging."""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session or session['proto'] != PROTO_UDP:
                logger.warning(f"[{client}] Invalid UDP session: {session_id}")
                self._send_encrypted(b"invalid_session")
                return
            session['last_active'] = time.time()
            session['requests'] += 1
        
        sock = session['socket']
        
        # Forward UDP packet to destination
        if data and data != b"CLOSE" and data != b"HEARTBEAT":
            try:
                addr = (session['host'], session['port'])
                sock.sendto(data, addr)
                session['bytes_sent'] += len(data)
                logger.debug(f"[{client}] Session {session_id}: Sent {len(data)} bytes UDP to {addr}")
            except Exception as e:
                logger.error(f"[{client}] Session {session_id}: UDP send error: {e}")
        elif data == b"HEARTBEAT":
            logger.debug(f"[{client}] Session {session_id}: UDP heartbeat")
        
        # Check for incoming UDP data
        response_data = b""
        try:
            ready = select.select([sock], [], [], 0.001)
            if ready[0]:
                data, addr = sock.recvfrom(65536)
                response_data = data
                session['bytes_received'] += len(data)
                logger.debug(f"[{client}] Session {session_id}: Received {len(data)} bytes UDP from {addr}")
        except (BlockingIOError, socket.error):
            pass
        
        self._send_encrypted(response_data if response_data else b"")
    
    def _send_encrypted(self, data_bytes):
        try:
            token = self.crypto.encrypt(data_bytes)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(token)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(token.encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            logger.error(f"Error sending response: {e}")
    
    def _generate_session_id(self):
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _close_session(self, session_id):
        with self.sessions_lock:
            if session_id in self.sessions:
                try:
                    self.sessions[session_id]['socket'].close()
                except:
                    pass
                del self.sessions[session_id]
                logger.debug(f"Session {session_id} removed from sessions")
    
    def log_message(self, format, *args):
        # Only log errors and important events
        if "200" not in str(args[0]) if args else True:
            logger.info(f"[{self.client_address[0]}] {format % args}")

class SessionCleaner(threading.Thread):
    def __init__(self, handler_class, cleanup_interval=30):
        super().__init__(daemon=True)
        self.handler_class = handler_class
        self.cleanup_interval = cleanup_interval
    
    def run(self):
        logger.info(f"Session cleaner started (interval: {self.cleanup_interval}s)")
        while True:
            time.sleep(self.cleanup_interval)
            with self.handler_class.sessions_lock:
                now = time.time()
                stale = []
                for sid, s in self.handler_class.sessions.items():
                    if s['proto'] == PROTO_UDP:
                        timeout = self.handler_class.udp_timeout
                    else:
                        timeout = self.handler_class.timeout
                    
                    age = now - s['last_active']
                    if age > timeout:
                        stale.append((sid, age, s['proto'], s.get('requests', 0)))
                
                for sid, age, proto, reqs in stale:
                    logger.info(f"Cleaning {proto} session {sid} (idle {age:.0f}s, {reqs} requests)")
                    try:
                        self.handler_class.sessions[sid]['socket'].close()
                    except:
                        pass
                    del self.handler_class.sessions[sid]
                
                if stale:
                    logger.info(f"Cleaned {len(stale)} stale sessions, {len(self.handler_class.sessions)} remaining")

def run_server(config_path="server_config.json"):
    if not os.path.exists(config_path):
        print(f"Config file {config_path} not found. Running setup wizard...")
        if not generate_config_wizard(config_path, "server"):
            print("Setup cancelled.")
            return
    
    with open(config_path) as f:
        config = json.load(f)
    
    logger.info("Loading server configuration...")
    logger.debug(f"Config: {json.dumps(config, indent=2)}")
    
    TunnelHandler.crypto = TunnelCrypto(config["encryption_key"])
    TunnelHandler.max_post_bytes = config["max_post_bytes"]
    TunnelHandler.timeout = config["timeout"]
    TunnelHandler.udp_timeout = config.get("udp_timeout", 60)
    
    cleanup_interval = config.get("cleanup_interval", 30)
    cleaner = SessionCleaner(TunnelHandler, cleanup_interval)
    cleaner.start()
    
    host, port = config["listen"].split(":")
    server = HTTPServer((host, int(port)), TunnelHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    logger.info(f"Tunnel server listening on {host}:{port}")
    logger.info(f"Max POST: {config['max_post_bytes']} bytes, TCP timeout: {config['timeout']}s, UDP timeout: {config.get('udp_timeout', 60)}s")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        server.shutdown()

if __name__ == "__main__":
    run_server()