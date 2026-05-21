import json
import socket
import threading
import time
import select
import os
import sys
import struct
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from common import TunnelCrypto, generate_config_wizard, UDPPacket

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads."""
    daemon_threads = True

class TunnelHandler(BaseHTTPRequestHandler):
    crypto = None
    max_post_bytes = 5242880
    timeout = 60
    sessions = {}
    sessions_lock = threading.Lock()
    
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > self.max_post_bytes:
                self.send_error(413)
                return
            
            body = self.rfile.read(content_length).decode()
            
            # Quick response to keep connection alive
            if not body:
                self._send_encrypted(b"")
                return
            
            try:
                plain = self.crypto.decrypt(body)
            except Exception:
                self.send_error(400)
                return
            
            # Parse message type
            try:
                msg = json.loads(plain.decode())
                if isinstance(msg, dict):
                    msg_type = msg.get("type")
                    if msg_type == "connect":
                        self._handle_connect(msg)
                    elif msg_type == "udp_associate":
                        self._handle_udp_associate(msg)
                    else:
                        self._send_encrypted(json.dumps({"status": "error", "reason": "Unknown type"}).encode())
                    return
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            
            # Handle session messages
            if b'::' in plain:
                parts = plain.split(b'::', 1)
                session_id = parts[0].decode('ascii', errors='ignore')
                message = parts[1]
                
                if session_id in self.sessions:
                    self._handle_session_message(session_id, message)
                else:
                    self._send_encrypted(b"invalid_session")
            else:
                self._send_encrypted(b"invalid_format")
                
        except Exception as e:
            print(f"Error: {e}")
            try:
                self.send_error(500)
            except:
                pass
    
    def _handle_connect(self, msg):
        """Handle TCP connect request."""
        host = msg.get("host")
        port = msg.get("port")
        
        try:
            dest_sock = socket.create_connection((host, port), timeout=10)
            dest_sock.setblocking(False)
            
            session_id = self._generate_session_id()
            with self.sessions_lock:
                self.sessions[session_id] = {
                    'type': 'tcp',
                    'socket': dest_sock,
                    'last_active': time.time(),
                    'host': host,
                    'port': port
                }
            
            print(f"TCP session {session_id}: {host}:{port}")
            self._send_encrypted(json.dumps({"status": "ok", "session": session_id}).encode())
            
        except Exception as e:
            print(f"Connect failed: {host}:{port}: {e}")
            self._send_encrypted(json.dumps({"status": "error", "reason": str(e)}).encode())
    
    def _handle_udp_associate(self, msg):
        """Handle UDP associate request."""
        session_id = self._generate_session_id()
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setblocking(False)
        
        with self.sessions_lock:
            self.sessions[session_id] = {
                'type': 'udp',
                'socket': udp_sock,
                'last_active': time.time(),
                'host': '0.0.0.0',
                'port': 0
            }
        
        print(f"UDP session {session_id} created")
        self._send_encrypted(json.dumps({"status": "ok", "session": session_id}).encode())
    
    def _handle_session_message(self, session_id, message):
        """Handle data for existing session."""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session:
                self._send_encrypted(b"invalid_session")
                return
            session['last_active'] = time.time()
        
        if message == b"CLOSE":
            self._close_session(session_id)
            self._send_encrypted(b"closed")
            return
        
        if message == b"HEARTBEAT":
            self._send_encrypted(b"")
            return
        
        if session['type'] == 'udp':
            self._handle_udp_data(session, message)
        else:
            self._handle_tcp_data(session, message)
    
    def _handle_tcp_data(self, session, data):
        """Handle TCP data forwarding."""
        dest_sock = session['socket']
        
        try:
            dest_sock.sendall(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self._close_session_by_socket(dest_sock)
            self._send_encrypted(b"destination_closed")
            return
        
        # Read response with timeout
        response = b""
        deadline = time.time() + 0.1  # 100ms max wait
        
        try:
            while time.time() < deadline:
                ready = select.select([dest_sock], [], [], 0.01)
                if ready[0]:
                    chunk = dest_sock.recv(65536)
                    if not chunk:
                        self._close_session_by_socket(dest_sock)
                        if not response:
                            response = b"destination_closed"
                        break
                    response += chunk
                    if len(response) >= self.max_post_bytes - 2000:
                        break
                else:
                    break
        except (BlockingIOError, BrokenPipeError, ConnectionResetError, OSError):
            pass
        
        self._send_encrypted(response)
    
    def _handle_udp_data(self, session, data):
        """Handle UDP data forwarding."""
        udp_sock = session['socket']
        
        # Data should contain SOCKS5 UDP packet
        packet_data, addr = UDPPacket.decode(data)
        if packet_data and addr:
            try:
                udp_sock.sendto(packet_data, addr)
            except Exception as e:
                print(f"UDP send error: {e}")
        
        # Read response
        response = b""
        try:
            ready = select.select([udp_sock], [], [], 0.05)
            if ready[0]:
                resp_data, resp_addr = udp_sock.recvfrom(65536)
                response = UDPPacket.encode(resp_data, resp_addr)
        except (BlockingIOError, OSError):
            pass
        
        self._send_encrypted(response)
    
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
    
    def _close_session_by_socket(self, sock):
        with self.sessions_lock:
            for sid, s in list(self.sessions.items()):
                if s['socket'] == sock:
                    try:
                        sock.close()
                    except:
                        pass
                    del self.sessions[sid]
                    break
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

class SessionCleaner(threading.Thread):
    def __init__(self, handler_class, cleanup_interval=120, session_timeout=60):
        super().__init__(daemon=True)
        self.handler_class = handler_class
        self.cleanup_interval = cleanup_interval
        self.session_timeout = session_timeout
    
    def run(self):
        while True:
            time.sleep(self.cleanup_interval)
            with self.handler_class.sessions_lock:
                now = time.time()
                stale = [
                    sid for sid, s in self.handler_class.sessions.items()
                    if now - s['last_active'] > self.session_timeout
                ]
                for sid in stale:
                    try:
                        self.handler_class.sessions[sid]['socket'].close()
                    except:
                        pass
                    del self.handler_class.sessions[sid]
                if stale:
                    print(f"Cleaned {len(stale)} stale sessions")

def run_server(config_path="server_config.json"):
    if not os.path.exists(config_path):
        print(f"Config not found. Running wizard...")
        if not generate_config_wizard(config_path, "server"):
            print("Setup cancelled.")
            return
    
    with open(config_path) as f:
        config = json.load(f)
    
    TunnelHandler.crypto = TunnelCrypto(config["encryption_key"])
    TunnelHandler.max_post_bytes = config["max_post_bytes"]
    TunnelHandler.timeout = config["timeout"]
    
    cleanup_interval = config.get("cleanup_interval", 120)
    cleaner = SessionCleaner(TunnelHandler, cleanup_interval, config["timeout"])
    cleaner.start()
    
    host, port = config["listen"].split(":")
    workers = config.get("workers", 10)
    server = ThreadingHTTPServer((host, int(port)), TunnelHandler)
    print(f"Tunnel server on {host}:{port} (workers: {workers})")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()

if __name__ == "__main__":
    run_server()