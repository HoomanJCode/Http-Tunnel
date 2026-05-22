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
from common import TunnelCrypto, generate_server_config, setup_logging, compress_data, decompress_data, COMPRESS_ZLIB, PROTO_TCP, PROTO_UDP

class TunnelHandler(BaseHTTPRequestHandler):
    crypto = None
    max_post_bytes = 5242880
    tcp_timeout = 60
    udp_timeout = 120
    sessions = {}
    sessions_lock = threading.Lock()
    executor = ThreadPoolExecutor(max_workers=50)
    logger = None
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
            
            # Handle ping/health check
            try:
                msg = json.loads(plain.decode())
                if isinstance(msg, dict) and msg.get("type") == "ping":
                    self._send_encrypted(b"pong")
                    return
                elif isinstance(msg, dict) and msg.get("type") == "connect":
                    self.logger.info(f"[{client}] CONNECT to {msg.get('host')}:{msg.get('port')}")
                    self._handle_connect(msg)
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
        """Resolve hostname and connect. Handles both IP and domain names."""
        # Check if it's already an IP address
        try:
            socket.inet_pton(socket.AF_INET, host)
            self.logger.info(f"Connecting to IPv4: {host}:{port}")
            sock = socket.create_connection((host, port), timeout=10)
            return sock
        except socket.error:
            pass
        
        try:
            socket.inet_pton(socket.AF_INET6, host)
            self.logger.info(f"Connecting to IPv6: {host}:{port}")
            try:
                sock = socket.create_connection((host, port), timeout=10)
                return sock
            except OSError as e:
                self.logger.error(f"IPv6 failed: {e}")
                raise
        except socket.error:
            pass
        
        # It's a hostname, resolve it
        self.logger.info(f"Resolving {host}:{port}...")
        try:
            addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addrs.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
            
            for family, socktype, proto, canonname, sockaddr in addrs:
                try:
                    self.logger.debug(f"Trying {sockaddr}")
                    sock = socket.socket(family, socktype, proto)
                    sock.settimeout(10)
                    sock.connect(sockaddr)
                    self.logger.info(f"Connected to {host} ({sockaddr[0]}:{sockaddr[1]})")
                    return sock
                except OSError as e:
                    self.logger.debug(f"Failed: {e}")
                    continue
            
            raise OSError(f"Could not connect to {host}:{port}")
        except socket.gaierror as e:
            raise OSError(f"DNS resolution failed for {host}: {e}")
    
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
                # Set TCP_NODELAY to disable Nagle's algorithm for lower latency
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
                    'idle_count': 0,
                    'pending_data': b''  # Buffer for data that couldn't be sent immediately
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
            session['idle_count'] = 0
            session['requests'] += 1
        
        sock = session['socket']
        
        # Handle control messages
        if message == b"CLOSE":
            self.logger.info(f"[{client}] Session {session_id} closed by client")
            self.logger.info(f"[{client}] Session stats: {session['requests']} req, {session['bytes_sent']}B sent, {session['bytes_received']}B recv")
            self._close_session(session_id)
            self._send_encrypted(b"closed")
            return
        
        # Decompress incoming data if needed
        if message and message != b"HEARTBEAT" and message != b"CLOSE":
            if self.compression:
                try:
                    message = decompress_data(message)
                except Exception:
                    pass
        
        # Forward data to destination
        if message and message != b"HEARTBEAT":
            try:
                # Send all data, handle partial sends
                total_sent = 0
                while total_sent < len(message):
                    try:
                        sent = sock.send(message[total_sent:])
                        if sent > 0:
                            total_sent += sent
                            session['bytes_sent'] += sent
                        else:
                            break
                    except BlockingIOError:
                        # Socket buffer full, wait and retry
                        ready = select.select([], [sock], [], 0.1)
                        if not ready[1]:
                            break
                self.logger.debug(f"[{client}] Session {session_id}: Sent {total_sent}/{len(message)} bytes to destination")
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                self.logger.error(f"[{client}] Session {session_id}: Write error: {e}")
                self._close_session(session_id)
                self._send_encrypted(b"destination_closed")
                return
            except Exception as e:
                self.logger.error(f"[{client}] Session {session_id}: Unexpected write error: {e}")
                self._close_session(session_id)
                self._send_encrypted(b"destination_closed")
                return
        
        # Read available data immediately
        response_data = b""
        try:
            while True:
                ready = select.select([sock], [], [], 0.01)  # Increased timeout slightly
                if ready[0]:
                    try:
                        chunk = sock.recv(65536)
                        if not chunk:
                            self.logger.info(f"[{client}] Session {session_id}: Destination closed (EOF)")
                            self._close_session(session_id)
                            response_data = b"destination_closed"
                            break
                        response_data += chunk
                        session['bytes_received'] += len(chunk)
                        self.logger.debug(f"[{client}] Session {session_id}: Received {len(chunk)} bytes from destination")
                        if len(response_data) >= self.max_post_bytes - 2000:
                            break
                    except BlockingIOError:
                        break
                    except (ConnectionResetError, BrokenPipeError) as e:
                        self.logger.info(f"[{client}] Session {session_id}: Connection reset by destination")
                        self._close_session(session_id)
                        response_data = b"destination_closed"
                        break
                else:
                    break
        except Exception as e:
            self.logger.error(f"[{client}] Session {session_id}: Read error: {e}")
            self._close_session(session_id)
            response_data = b"destination_closed"
        
        # Compress response if needed
        if response_data and response_data != b"destination_closed" and response_data != b"closed":
            if self.compression:
                try:
                    response_data = compress_data(response_data, self.compress_method, self.compress_threshold)
                except Exception:
                    pass
        
        # Always send response
        if response_data:
            self.logger.debug(f"[{client}] Session {session_id}: Sending {len(response_data)} bytes response to client")
        self._send_encrypted(response_data if response_data else b"")
    
    def _handle_udp_data(self, client, session_id, data):
        """Handle UDP data."""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session or session['proto'] != PROTO_UDP:
                self._send_encrypted(b"invalid_session")
                return
            session['last_active'] = time.time()
            session['idle_count'] = 0
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
                except Exception:
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
                    
                    age = now - s['last_active']
                    if age > timeout * 0.5:
                        s['idle_count'] = s.get('idle_count', 0) + 1
                    else:
                        s['idle_count'] = 0
                    
                    if age > timeout and s.get('idle_count', 0) > 3:
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
    
    # Setup logging
    logger = setup_logging(config, "server")
    logger.info("Loading server configuration...")
    
    TunnelHandler.logger = logger
    TunnelHandler.crypto = TunnelCrypto(config["encryption_key"])
    TunnelHandler.max_post_bytes = config["max_post_bytes"]
    TunnelHandler.tcp_timeout = config["tcp_timeout"]
    TunnelHandler.udp_timeout = config["udp_timeout"]
    TunnelHandler.compression = config.get("compression", True)
    
    cleanup_interval = config.get("cleanup_interval", 30)
    cleaner = SessionCleaner(TunnelHandler, cleanup_interval)
    cleaner.start()
    
    host, port = config["listen"].split(":")
    server = HTTPServer((host, int(port)), TunnelHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    logger.info(f"Listening on {host}:{port}")
    logger.info(f"TCP timeout: {config['tcp_timeout']}s, UDP timeout: {config['udp_timeout']}s")
    logger.info(f"Compression: {'ON' if config['compression'] else 'OFF'}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()

if __name__ == "__main__":
    run_server()