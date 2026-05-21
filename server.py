import json
import socket
import threading
import time
import select
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from common import TunnelCrypto, generate_config_wizard

class TunnelHandler(BaseHTTPRequestHandler):
    crypto = None
    max_post_bytes = 5242880
    timeout = 30
    sessions = {}
    sessions_lock = threading.Lock()
    
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
            
            # Parse the message format
            # Could be: session_id::data or session_id::HEARTBEAT or session_id::CLOSE
            # Or legacy connect: {"type": "connect", "host": "...", "port": ...}
            
            try:
                # Try JSON first (for connect requests)
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
                    self._handle_session_message(session_id, message)
                else:
                    print(f"Unknown session: {session_id}")
                    self._send_encrypted(b"invalid_session")
            else:
                print(f"Invalid message format")
                self._send_encrypted(b"invalid_format")
                
        except BrokenPipeError:
            # Client disconnected, ignore
            pass
        except Exception as e:
            print(f"Error handling POST: {e}")
            try:
                self.send_error(500)
            except:
                pass
    
    def _handle_connect(self, msg):
        """Handle initial connection request."""
        host = msg.get("host")
        port = msg.get("port")
        
        if not host or not port:
            resp = json.dumps({"status": "error", "reason": "Missing host/port"})
            self._send_encrypted(resp.encode())
            return
        
        try:
            print(f"Connecting to {host}:{port}...")
            dest_sock = socket.create_connection((host, port), timeout=10)
            dest_sock.setblocking(False)
            
            session_id = self._generate_session_id()
            with self.sessions_lock:
                self.sessions[session_id] = {
                    'socket': dest_sock,
                    'last_active': time.time(),
                    'host': host,
                    'port': port,
                    'created': time.time()
                }
            
            print(f"Session {session_id} created for {host}:{port}")
            resp = json.dumps({"status": "ok", "session": session_id})
            self._send_encrypted(resp.encode())
            
        except Exception as e:
            print(f"Connection failed to {host}:{port}: {e}")
            resp = json.dumps({"status": "error", "reason": str(e)})
            self._send_encrypted(resp.encode())
    
    def _handle_session_message(self, session_id, message):
        """Handle data/control messages for existing session."""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session:
                self._send_encrypted(b"invalid_session")
                return
            session['last_active'] = time.time()
        
        dest_sock = session['socket']
        
        # Handle control messages
        if message == b"CLOSE":
            print(f"Session {session_id} closed by client")
            self._close_session(session_id)
            self._send_encrypted(b"closed")
            return
        
        # Forward data to destination (skip heartbeats)
        if message and message != b"HEARTBEAT":
            try:
                dest_sock.sendall(message)
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                print(f"Session {session_id}: Destination write error: {e}")
                self._close_session(session_id)
                self._send_encrypted(b"destination_closed")
                return
        
        # Read from destination
        response_data = b""
        try:
            while True:
                ready = select.select([dest_sock], [], [], 0.01)
                if ready[0]:
                    chunk = dest_sock.recv(8192)
                    if not chunk:
                        print(f"Session {session_id}: Destination closed connection")
                        self._close_session(session_id)
                        response_data = b"destination_closed"
                        break
                    response_data += chunk
                    if len(response_data) >= self.max_post_bytes - 2000:
                        break
                else:
                    break
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"Session {session_id}: Destination read error: {e}")
            self._close_session(session_id)
            response_data = b"destination_closed"
        
        self._send_encrypted(response_data if response_data else b"")
    
    def _send_encrypted(self, data_bytes):
        """Send encrypted response to client."""
        try:
            token = self.crypto.encrypt(data_bytes)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(token)))
            self.end_headers()
            self.wfile.write(token.encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Client disconnected - that's OK
            pass
        except Exception as e:
            print(f"Error sending response: {e}")
    
    def _generate_session_id(self):
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _close_session(self, session_id):
        """Clean up a session."""
        with self.sessions_lock:
            if session_id in self.sessions:
                try:
                    self.sessions[session_id]['socket'].close()
                except:
                    pass
                del self.sessions[session_id]
    
    def log_message(self, format, *args):
        """Override to add custom logging."""
        if args:
            print(f"[{self.client_address[0]}] {format % args}")

class SessionCleaner(threading.Thread):
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
                    print(f"Cleaning up stale session {sid} (idle for {now - self.handler_class.sessions[sid]['last_active']:.0f}s)")
                    try:
                        self.handler_class.sessions[sid]['socket'].close()
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