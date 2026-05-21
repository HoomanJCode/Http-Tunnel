import json
import socket
import threading
import select
from http.server import HTTPServer, BaseHTTPRequestHandler
from common import TunnelCrypto, create_connect_message, create_close_message

class TunnelHandler(BaseHTTPRequestHandler):
    crypto = None
    max_post_bytes = 65536
    timeout = 30
    # session -> destination socket
    sessions = {}
    sessions_lock = threading.Lock()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > self.max_post_bytes:
            self.send_error(413)
            return

        body = self.rfile.read(content_length).decode()
        try:
            plain = self.crypto.decrypt(body)
        except Exception:
            self.send_error(400, "Decryption failed")
            return

        try:
            msg = json.loads(plain)
        except:
            msg = None

        # Connection setup
        if isinstance(msg, dict) and msg.get("type") == "connect":
            host = msg["host"]
            port = msg["port"]
            try:
                dest_sock = socket.create_connection((host, port), timeout=self.timeout)
                dest_sock.setblocking(False)
            except Exception as e:
                resp = json.dumps({"status": "error", "reason": str(e)})
                self._send_encrypted(resp)
                return
            session_id = str(hash(f"{host}:{port}-{id(dest_sock)}"))  # simple unique ID
            with self.sessions_lock:
                self.sessions[session_id] = dest_sock
            resp = json.dumps({"status": "ok", "session": session_id})
            self._send_encrypted(resp)
            return

        # Connection close
        if isinstance(msg, dict) and msg.get("type") == "close":
            # The session ID is not directly present; we identify by client IP:port?
            # In a real implementation, you'd include session in each POST.
            # For simplicity, we assume a single session per client IP.
            # (You should extend the protocol to include session ID in every POST.)
            # Here we just ignore close and let timeout clean up.
            self._send_encrypted("ok")
            return

        # Data relay: plain is either binary data or "HEARTBEAT"
        # We need the session ID. For demo, we use client address as session key.
        client_key = self.client_address[0]
        dest_sock = self.sessions.get(client_key)
        if not dest_sock:
            # No active session – ignore
            self._send_encrypted("")
            return

        if plain != b"HEARTBEAT":
            # Send to destination
            try:
                dest_sock.sendall(plain)
            except (BrokenPipeError, ConnectionResetError):
                self._close_session(client_key)
                self._send_encrypted("")
                return

        # Read from destination (non‑blocking, up to max bytes)
        response_data = b""
        try:
            while True:
                ready = select.select([dest_sock], [], [], 0.05)
                if ready[0]:
                    chunk = dest_sock.recv(4096)
                    if not chunk:
                        raise ConnectionResetError()
                    response_data += chunk
                    if len(response_data) >= self.max_post_bytes - 400:
                        break
                else:
                    break
        except (BlockingIOError, ConnectionResetError):
            pass

        self._send_encrypted(response_data)

    def _send_encrypted(self, data_bytes):
        if isinstance(data_bytes, str):
            data_bytes = data_bytes.encode()
        token = self.crypto.encrypt(data_bytes)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(token.encode())

    def _close_session(self, client_key):
        with self.sessions_lock:
            sock = self.sessions.pop(client_key, None)
            if sock:
                sock.close()

def run_server(config_path="server_config.json"):
    with open(config_path) as f:
        config = json.load(f)
    TunnelHandler.crypto = TunnelCrypto(config["encryption_key"])
    TunnelHandler.max_post_bytes = config["max_post_bytes"]
    TunnelHandler.timeout = config["timeout"]
    host, port = config["listen"].split(":")
    server = HTTPServer((host, int(port)), TunnelHandler)
    print(f"Tunnel server listening on {host}:{port}")
    server.serve_forever()

if __name__ == "__main__":
    run_server()
