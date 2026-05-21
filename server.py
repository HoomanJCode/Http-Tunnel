import json
import socket
import threading
import time
import select
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from common import TunnelCrypto, generate_config_wizard

class TunnelHandler(BaseHTTPRequestHandler):
    crypto = None
    max_post_bytes = 5242880
    timeout = 30
    sessions = {}  # {session_id: {'socket': sock, 'last_active': timestamp}}
    sessions_lock = threading.Lock()
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > self.max_post_bytes:
            self.send_error(413, "Payload too large")
            return
        
        body = self.rfile.read(content_length).decode()
        try:
            plain = self.crypto.decrypt(body)
        except Exception:
            self.send_error(400, "Decryption failed")
            return
        
        # Parse the prefixed session_id and message
        try:
            # Format: session_id::message
            if b'::' in plain:
                parts = plain.split(b'::', 1)
                session_id = parts[0].decode()
                message = parts[1]
            else:
                # Legacy format for connect requests
                msg = json.loads(plain)
                session_id = None
                message = None
        except:
            self.send_error(400, "Invalid message format")
            return
        
        # Handle CONNECT request
        if session_id is None and message is None:
            try:
                msg = json.loads(plain)
                if msg.get("type") == "connect":
                    host = msg["host"]
                    port = msg["port"]
                    try:
                        dest_sock = socket.create_connection((host, port), timeout=self.timeout)
                        dest_sock.setblocking(False)
                    except Exception as e:
                        resp = json.dumps({"status": "error", "reason": str(e)})
                        self._send_encrypted(resp.encode())
                        return
                    
                    session_id = self._generate_session_id()
                    with self.sessions_lock:
                        self.sessions[session_id] = {
                            'socket': dest_sock,
                            'last_active': time.time(),
                            'host': host,
                            'port': port
                        }
                    
                    resp = json.dumps({"status": "ok", "session": session_id})
                    self._send_encrypted(resp.encode())
                    return
            except:
                pass
        
        # Handle existing session
        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            session['last_active'] = time.time()
            dest_sock = session['socket']
            
            # Handle CLOSE request
            if message == b"CLOSE":
                self._close_session(session_id)
                self._send_encrypted(b"closed")
                return
            
            # Send data to destination (skip heartbeats)
            if message and message != b"HEARTBEAT":
                try:
                    dest_sock.sendall(message)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    self._close_session(session_id)
                    self._send_encrypted(b"destination_closed")
                    return
            
            # Read from destination
            response_data = b""
            try:
                while True:
                    ready = select.select([dest_sock], [], [], 0.01)
                    if ready[0]:
                        chunk = dest_sock.recv(4096)
                        if not chunk:
                            self._close_session(session_id)
                            response_data = b"destination_closed"
                            break
                        response_data += chunk
                        if len(response_data) >= self.max_post_bytes - 1000:
                            break
                    else:
                        break
            except Exception:
                self._close_session(session_id)
                response_data = b"destination_closed"
            
            self._send_encrypted(response_data if response_data else b"")
        else:
            self._send_encrypted(b"invalid_session")
    
    def _send_encrypted(self, data_bytes):
        token = self.crypto.encrypt(data_bytes)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(token)))
        self.end_headers()
        self.wfile.write(token.encode())
    
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
        # Suppress default logging
        pass

class SessionCleaner(threading.Thread):
    """Clean up stale sessions periodically."""
    def __init__(self, handler_class, cleanup_interval=60, session_timeout=30):
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
                    print(f"Cleaned up {len(stale)} stale sessions")

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
    
    # Start session cleaner
    cleanup_interval = config.get("cleanup_interval", 60)
    cleaner = SessionCleaner(TunnelHandler, cleanup_interval, config["timeout"])
    cleaner.start()
    
    host, port = config["listen"].split(":")
    server = HTTPServer((host, int(port)), TunnelHandler)
    print(f"Tunnel server listening on {host}:{port}")
    print(f"Max POST size: {config['max_post_bytes']} bytes")
    print(f"Session timeout: {config['timeout']}s")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()

if __name__ == "__main__":
    run_server()