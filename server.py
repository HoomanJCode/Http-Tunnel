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
from common import TunnelCrypto, generate_server_config, setup_logging, PROTO_TCP, PROTO_UDP, compress_data, decompress_data, COMPRESS_ZLIB, StreamManager

class ConnectionPool:
    """Manages persistent connections for HTTP keep-alive."""
    def __init__(self, max_connections=50):
        self.max_connections = max_connections
        self.active_connections = 0
        self.lock = threading.Lock()
    
    def acquire(self):
        """Acquire connection slot."""
        with self.lock:
            if self.active_connections < self.max_connections:
                self.active_connections += 1
                return True
            return False
    
    def release(self):
        """Release connection slot."""
        with self.lock:
            if self.active_connections > 0:
                self.active_connections -= 1

class TunnelHandler(BaseHTTPRequestHandler):
    crypto = None
    max_post_bytes = 5242880
    tcp_timeout = 60
    udp_timeout = 120
    sessions = {}
    sessions_lock = threading.Lock()
    executor = ThreadPoolExecutor(max_workers=50)
    logger = None
    connection_pool = ConnectionPool()
    stream_manager = StreamManager()
    compression = True
    compress_method = COMPRESS_ZLIB
    compress_threshold = 100
    
    def do_POST(self):
        client = self.client_address[0]
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            
            if content_length > self.max_post_bytes:
                self.logger.warning(f"[{client}] Payload too large: {content_length}")
                self.send_error(413, "Payload too large")
                return
            
            body = self.rfile.read(content_length).decode()
            
            try:
                plain = self.crypto.decrypt(body)
            except Exception as e:
                self.logger.warning(f"[{client}] Decryption failed")
                self.send_error(400, "Decryption failed")
                return
            
            # Parse the message
            try:
                msg = json.loads(plain.decode())
                if isinstance(msg, dict) and msg.get("type") == "connect":
                    self.logger.info(f"[{client}] CONNECT to {msg.get('host')}:{msg.get('port')}")
                    self._handle_connect(msg)
                    return
                elif isinstance(msg, dict) and msg.get("type") == "ping":
                    # Health check response
                    self._send_encrypted(b"pong")
                    return
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            
            # Handle session-prefixed messages
            if b'::' in plain:
                parts = plain.split(b'::', 1)
                session_id = parts[0].decode('ascii', errors='ignore')
                message = parts[1] if len(parts) > 1 else b""
                
                if session_id in self.sessions:
                    if message.startswith(b"UDP:"):
                        self._handle_udp_data(client, session_id, message[4:])
                    else:
                        self._handle_tcp_data(client, session_id, message)
                else:
                    self.logger.warning(f"[{client}] Unknown session: {session_id}")
                    self._send_encrypted(b"invalid_session")
            else:
                self.logger.warning(f"[{client}] Invalid format")
                self._send_encrypted(b"invalid_format")
                
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self.logger.error(f"[{client}] Error: {e}")
            try:
                self.send_error(500)
            except:
                pass
    
    def _resolve_and_connect(self, host, port):
        """Resolve hostname and connect."""
        self.logger.info(f"Resolving {host}:{port}")
        
        # Check if it's an IPv6 address
        try:
            socket.inet_pton(socket.AF_INET6, host)
            try:
                sock = socket.create_connection((host, port), timeout=10)
                self.logger.info(f"IPv6 connected")
                return sock
            except OSError as e:
                self.logger.error(f"IPv6 failed: {e}")
                raise
        except socket.error:
            pass
        
        # Try to resolve as hostname, prefer IPv4
        try:
            addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addrs.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
            
            for family, socktype, proto, canonname, sockaddr in addrs:
                try:
                    sock = socket.socket(family, socktype, proto)
                    sock.settimeout(10)
                    sock.connect(sockaddr)
                    self.logger.info(f"Connected to {sockaddr}")
                    return sock
                except OSError as e:
                    self.logger.debug(f"Failed: {e}")
                    continue
            
            raise OSError(f"Could not connect to any address")
        except socket.gaierror as e:
            raise OSError(f"DNS failed: {e}")
    
    def _handle_connect(self, msg):
        host = msg.get("host")
        port = msg.get("port")
        proto = msg.get("proto", PROTO_TCP)
        
        if not host or not port:
            resp = json.dumps({"status": "error", "reason": "Missing host/port"})
            self._send_encrypted(resp.encode())
            return
        
        try:
            session_id = self._generate_session_id()
            
            if proto == PROTO_UDP:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                self.logger.info(f"UDP session {session_id} for {host}:{port}")
            else:
                sock = self._resolve_and_connect(host, port)
                sock.setblocking(False)
                self.logger.info(f"TCP session {session_id} for {host}:{port}")
            
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
                    'requests': 0,
                    'idle_count': 0
                }
            
            resp = json.dumps({"status": "ok", "session": session_id, "proto": proto})
            self._send_encrypted(resp.encode())
            
        except Exception as e:
            self.logger.error(f"Connection failed to {host}:{port}: {e}")
            resp = json.dumps({"status": "error", "reason": str(e)})
            self._send_encrypted(resp.encode())
    
    def _handle_tcp_data(self, client, session_id, message):
        """Handle TCP data messages."""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session or session['proto'] != PROTO_TCP:
                self._send_encrypted(b"invalid_session")
                return
            session['last_active'] = time.time()
            session['requests'] += 1
        
        sock = session['socket']
        
        # Handle control messages
        if message == b"CLOSE":
            self.logger.info(f"[{client}] Session {session_id} closed")
            self.logger.debug(f"[{client}] Stats: {session['requests']} req, {session['bytes_sent']}B sent, {session['bytes_received']}B recv")
            self._close_session(session_id)
            self._send_encrypted(b"closed")
            return
        
        # Decompress incoming data if needed
        if message and message != b"HEARTBEAT" and message != b"CLOSE":
            if self.compression:
                try:
                    message = decompress_data(message)
                except Exception as e:
                    self.logger.warning(f"[{client}] Decompression failed: {e}")
        
        # Forward data to destination
        if message and message != b"HEARTBEAT":
            try:
                sock.sendall(message)
                session['bytes_sent'] += len(message)
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                self.logger.error(f"[{client}] Session {session_id}: Write error")
                self._close_session(session_id)
                self._send_encrypted(b"destination_closed")
                return
        
        # Read available data immediately
        response_data = b""
        try:
            while True:
                ready = select.select([sock], [], [], 0.001)
                if ready[0]:
                    chunk = sock.recv(65536)
                    if not chunk:
                        self.logger.info(f"[{client}] Session {session_id}: Destination closed")
                        self._close_session(session_id)
                        response_data = b"destination_closed"
                        break
                    response_data += chunk
                    session['bytes_received'] += len(chunk)
                    if len(response_data) >= self.max_post_bytes - 2000:
                        break
                else:
                    break
        except (BlockingIOError, socket.error):
            pass
        except Exception as e:
            self.logger.error(f"[{client}] Session {session_id}: Read error")
            self._close_session(session_id)
            response_data = b"destination_closed"
        
        # Compress response if needed
        if response_data and response_data != b"destination_closed":
            if self.compression:
                try:
                    response_data = compress_data(response_data, self.compress_method, self.compress_threshold)
                except Exception as e:
                    self.logger.warning(f"[{client}] Compression failed: {e}")
        
        self._send_encrypted(response_data if response_data else b"")
    
    def _handle_udp_data(self, client, session_id, data):
        """Handle UDP data."""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session or session['proto'] != PROTO_UDP:
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
            except Exception as e:
                self.logger.error(f"[{client}] Session {session_id}: UDP send error")
        
        # Check for incoming UDP data
        response_data = b""
        try:
            ready = select.select([sock], [], [], 0.001)
            if ready[0]:
                data, addr = sock.recvfrom(65536)
                response_data = data
                session['bytes_received'] += len(data)
        except (BlockingIOError, socket.error):
            pass
        
        # Compress response if needed
        if response_data:
            if self.compression:
                try:
                    response_data = compress_data(response_data, self.compress_method, self.compress_threshold)
                except Exception as e:
                    self.logger.warning(f"[{client}] Compression failed: {e}")
        
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
            self.logger.error(f"Send error: {e}")
    
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
    
    def log_message(self, format, *args):
        if args and "200" not in str(args[0]):
            self.logger.debug(f"[{self.client_address[0]}] {format % args}")

class SessionCleaner(threading.Thread):
    def __init__(self, handler_class, cleanup_interval=30):
        super().__init__(daemon=True)
        self.handler_class = handler_class
        self.cleanup_interval = cleanup_interval
        self.logger = logging.getLogger("server.cleaner")
    
    def run(self):
        self.logger.info(f"Cleaner started ({self.cleanup_interval}s)")
        while True:
            time.sleep(self.cleanup_interval)
            with self.handler_class.sessions_lock:
                now = time.time()
                stale = []
                for sid, s in self.handler_class.sessions.items():
                    if s['proto'] == PROTO_UDP:
                        timeout = self.handler_class.udp_timeout
                    else:
                        timeout = self.handler_class.tcp_timeout
                    
                    # Adaptive timeout based on activity pattern
                    age = now - s['last_active']
                    if 'idle_count' not in s:
                        s['idle_count'] = 0
                    
                    if age > timeout * 0.5:
                        s['idle_count'] += 1
                    else:
                        s['idle_count'] = 0
                    
                    # Remove if truly stale (inactive > timeout with idle count)
                    if age > timeout and s['idle_count'] > 3:
                        stale.append((sid, age, s['proto'], s.get('requests', 0)))
                
                for sid, age, proto, reqs in stale:
                    self.logger.info(f"Clean {proto} session {sid} (idle {age:.0f}s, {reqs} req)")
                    try:
                        self.handler_class.sessions[sid]['socket'].close()
                    except:
                        pass
                    del self.handler_class.sessions[sid]

def run_server(config_path="server_config.json"):
    if not os.path.exists(config_path):
        print(f"Config file {config_path} not found. Running setup wizard...")
        if not generate_server_config(config_path):
            print("Setup cancelled.")
            return
    
    with open(config_path) as f:
        config = json.load(f)
    
    # Server-specific defaults
    config.setdefault("max_post_bytes", 5242880)
    config.setdefault("tcp_timeout", 60)
    config.setdefault("udp_timeout", 120)
    config.setdefault("cleanup_interval", 30)
    config.setdefault("log_level", "INFO")
    config.setdefault("compression", True)
    config.setdefault("compress_threshold", 100)
    
    # Setup logging
    logger = setup_logging(config, "server")
    logger.info("Loading server configuration...")
    logger.debug(f"Listen: {config['listen']}")
    
    TunnelHandler.logger = logger
    TunnelHandler.crypto = TunnelCrypto(config["encryption_key"])
    TunnelHandler.max_post_bytes = config["max_post_bytes"]
    TunnelHandler.tcp_timeout = config["tcp_timeout"]
    TunnelHandler.udp_timeout = config["udp_timeout"]
    
    # Compression settings
    TunnelHandler.compression = config.get("compression", True)
    TunnelHandler.compress_method = COMPRESS_ZLIB
    TunnelHandler.compress_threshold = config.get("compress_threshold", 100)
    logger.info(f"Compression: {'enabled' if TunnelHandler.compression else 'disabled'}")
    
    cleanup_interval = config.get("cleanup_interval", 30)
    cleaner = SessionCleaner(TunnelHandler, cleanup_interval)
    cleaner.start()
    
    host, port = config["listen"].split(":")
    server = HTTPServer((host, int(port)), TunnelHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    logger.info(f"Listening on {host}:{port}")
    logger.info(f"TCP timeout: {config['tcp_timeout']}s, UDP timeout: {config['udp_timeout']}s")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()

if __name__ == "__main__":
    run_server()