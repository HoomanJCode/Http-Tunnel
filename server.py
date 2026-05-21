import json
import socket
import threading
import time
import select
import os
import sys
import struct
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from common import TunnelCrypto, generate_config_wizard, PROTO_TCP, PROTO_UDP

class TunnelHandler(BaseHTTPRequestHandler):
    crypto = None
    max_post_bytes = 5242880
    timeout = 30
    udp_timeout = 60
    sessions = {}
    sessions_lock = threading.Lock()
    executor = ThreadPoolExecutor(max_workers=50)
    
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > self.max_post_bytes:
                self.send_error(413, "Payload too large")
                return
            
            body = self.rfile.read(content_length).decode()
            try:
                plain = self.crypto.decrypt(body)
            except Exception as e:
                print(f"Decryption failed: {e}")
                self.send_error(400, "Decryption failed")
                return
            
            # Parse the message
            try:
                msg = json.loads(plain.decode())
                if isinstance(msg, dict) and msg.get("type") == "connect":
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
                    # Check if it's a UDP packet
                    if message.startswith(b"UDP:"):
                        self._handle_udp_data(session_id, message[4:])
                    else:
                        self._handle_tcp_data(session_id, message)
                else:
                    self._send_encrypted(b"invalid_session")
            else:
                self._send_encrypted(b"invalid_format")
                
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            print(f"Error handling POST: {e}")
            try:
                self.send_error(500)
            except:
                pass
    
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
                # Create UDP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                print(f"UDP session {session_id} created for {host}:{port}")
            else:
                # Create TCP connection
                print(f"Connecting TCP to {host}:{port}...")
                sock = socket.create_connection((host, port), timeout=10)
                sock.setblocking(False)
                print(f"TCP session {session_id} created for {host}:{port}")
            
            with self.sessions_lock:
                self.sessions[session_id] = {
                    'socket': sock,
                    'last_active': time.time(),
                    'host': host,
                    'port': port,
                    'proto': proto,
                    'created': time.time(),
                    'pending_tcp_data': b"",
                    'udp_buffer': []
                }
            
            resp = json.dumps({"status": "ok", "session": session_id, "proto": proto})
            self._send_encrypted(resp.encode())
            
        except Exception as e:
            print(f"Connection failed to {host}:{port}: {e}")
            resp = json.dumps({"status": "error", "reason": str(e)})
            self._send_encrypted(resp.encode())
    
    def _handle_tcp_data(self, session_id, message):
        """Handle TCP data messages - respond immediately."""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session or session['proto'] != PROTO_TCP:
                self._send_encrypted(b"invalid_session")
                return
            session['last_active'] = time.time()
        
        sock = session['socket']
        
        # Handle control messages
        if message == b"CLOSE":
            print(f"TCP session {session_id} closed by client")
            self._close_session(session_id)
            self._send_encrypted(b"closed")
            return
        
        # Forward data to destination
        if message and message != b"HEARTBEAT":
            try:
                sock.sendall(message)
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                print(f"TCP session {session_id}: Write error: {e}")
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
                        print(f"TCP session {session_id}: Destination closed")
                        self._close_session(session_id)
                        response_data = b"destination_closed"
                        break
                    response_data += chunk
                    if len(response_data) >= self.max_post_bytes - 2000:
                        break
                else:
                    break
        except (BlockingIOError, socket.error):
            pass
        except Exception as e:
            print(f"TCP session {session_id}: Read error: {e}")
            self._close_session(session_id)
            response_data = b"destination_closed"
        
        # Always respond immediately
        self._send_encrypted(response_data if response_data else b"")
    
    def _handle_udp_data(self, session_id, data):
        """Handle UDP data - respond with any pending data."""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session or session['proto'] != PROTO_UDP:
                self._send_encrypted(b"invalid_session")
                return
            session['last_active'] = time.time()
        
        sock = session['socket']
        
        # Forward UDP packet to destination
        if data and data != b"CLOSE" and data != b"HEARTBEAT":
            try:
                addr = (session['host'], session['port'])
                sock.sendto(data, addr)
            except Exception as e:
                print(f"UDP session {session_id}: Send error: {e}")
        
        # Check for incoming UDP data
        response_data = b""
        try:
            ready = select.select([sock], [], [], 0.001)
            if ready[0]:
                data, addr = sock.recvfrom(65536)
                response_data = data
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
            print(f"Error sending response: {e}")
    
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
        # Suppress default logging for normal operations
        if args and "200" in str(args[0]):
            return  # Don't log successful requests
        print(f"[{self.client_address[0]}] {format % args}")

class SessionCleaner(threading.Thread):
    def __init__(self, handler_class, cleanup_interval=30):
        super().__init__(daemon=True)
        self.handler_class = handler_class
        self.cleanup_interval = cleanup_interval
    
    def run(self):
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
                    
                    if now - s['last_active'] > timeout:
                        stale.append(sid)
                
                for sid in stale:
                    s = self.handler_class.sessions[sid]
                    age = now - s['last_active']
                    print(f"Cleaning {s['proto']} session {sid} (idle {age:.0f}s)")
                    try:
                        s['socket'].close()
                    except:
                        pass
                    del self.handler_class.sessions[sid]

def run_server(config_path="server_config.json"):
    if not os.path.exists(config_path):
        print(f"Config file {config_path} not found. Running setup wizard...")
        if not generate_config_wizard(config_path, "server"):
            print("Setup cancelled.")
            return
    
    with open(config_path) as f:
        config = json.load(f)
    
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
    print(f"Tunnel server listening on {host}:{port}")
    print(f"Max POST size: {config['max_post_bytes']} bytes")
    print(f"TCP timeout: {config['timeout']}s, UDP timeout: {config.get('udp_timeout', 60)}s")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()

if __name__ == "__main__":
    run_server()