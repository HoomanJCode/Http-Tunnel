import json
import socket
import threading
import time
import select
import os
import requests
from common import TunnelCrypto, generate_config_wizard

class SocksToHttpTunnel:
    def __init__(self, config_path="client_config.json"):
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_config_wizard(config_path, "client"):
                raise RuntimeError("Setup cancelled.")
        
        with open(config_path) as f:
            self.config = json.load(f)
        
        self.crypto = TunnelCrypto(self.config["encryption_key"])
        self.server_url = self.config["server_url"]
        self.proxies = {}
        if self.config.get("outbound_http_proxy"):
            self.proxies = {
                "http": self.config["outbound_http_proxy"],
                "https": self.config["outbound_http_proxy"]
            }
        
        self.max_bytes = self.config["max_post_bytes"]
        self.batch_wait = self.config["batch_wait"]
        self.heartbeat_interval = self.config["heartbeat_interval"]
        self.http_timeout = self.config.get("http_timeout", 10)
        self.reconnect_delay = self.config.get("reconnect_delay", 1)
        
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        self.running = True

    def _http_post(self, body: str) -> str:
        """Send POST and return text response body with retry logic."""
        for attempt in range(3):
            try:
                resp = requests.post(
                    self.server_url,
                    data=body,
                    headers={"Content-Type": "text/plain"},
                    proxies=self.proxies if self.proxies else None,
                    timeout=self.http_timeout
                )
                resp.raise_for_status()
                return resp.text
            except Exception as e:
                if attempt == 2:
                    raise
                time.sleep(self.reconnect_delay * (attempt + 1))
    
    def handle_socks_connection(self, local_conn: socket.socket):
        """Handle SOCKS5 connection and tunnel it through HTTP."""
        session_id = None
        try:
            # SOCKS5 handshake
            local_conn.settimeout(10)
            ver, nmethods = local_conn.recv(2)
            methods = local_conn.recv(nmethods)
            local_conn.sendall(b"\x05\x00")  # No authentication
            
            # SOCKS5 request
            ver, cmd, rsv, atyp = local_conn.recv(4)
            if cmd != 1:  # CONNECT only
                local_conn.close()
                return
            
            # Parse target address
            if atyp == 1:  # IPv4
                addr = socket.inet_ntoa(local_conn.recv(4))
            elif atyp == 3:  # Domain name
                length = local_conn.recv(1)[0]
                addr = local_conn.recv(length).decode()
            else:
                local_conn.close()
                return
            port = int.from_bytes(local_conn.recv(2), 'big')
            
            print(f"SOCKS5 connect request: {addr}:{port}")
            
            # Send success response
            local_conn.sendall(
                b"\x05\x00\x00\x01" + 
                socket.inet_aton("0.0.0.0") + 
                port.to_bytes(2, 'big')
            )
            
            # Establish tunnel with server
            connect_msg = f'{{"type": "connect", "host": "{addr}", "port": {port}}}'
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect)
            data = json.loads(self.crypto.decrypt(resp).decode())
            
            if data.get("status") != "ok":
                print(f"Server refused connection: {data}")
                local_conn.close()
                return
            
            session_id = data["session"]
            print(f"Tunnel established: {session_id}")
            
            # Data relay loop
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            
            while self.running and session_id:
                now = time.time()
                
                # Read from local application
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            # Local app closed connection
                            self._send_close(session_id)
                            local_conn.close()
                            return
                        buffer_out += chunk
                        if len(buffer_out) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError):
                    break
                
                # Determine if we should send
                force_send = (
                    len(buffer_out) > 0 and
                    (len(buffer_out) >= self.max_bytes - 2000 or
                     now - last_send >= self.batch_wait)
                )
                
                heartbeat = (
                    len(buffer_out) == 0 and 
                    now - last_send >= self.heartbeat_interval
                )
                
                if force_send or heartbeat:
                    # Prepare payload
                    if len(buffer_out) > 0:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                    else:
                        payload = b"HEARTBEAT"
                    
                    # Prefix with session_id
                    message = session_id.encode() + b"::" + payload
                    enc_message = self.crypto.encrypt(message)
                    
                    try:
                        resp_text = self._http_post(enc_message)
                    except Exception as e:
                        print(f"HTTP POST error: {e}, reconnecting...")
                        time.sleep(self.reconnect_delay)
                        continue
                    
                    try:
                        plain = self.crypto.decrypt(resp_text)
                    except Exception:
                        print("Decryption failed")
                        continue
                    
                    # Handle server messages
                    if plain == b"destination_closed":
                        print("Destination closed connection")
                        break
                    elif plain == b"invalid_session":
                        print("Session expired, reconnecting...")
                        # Re-establish session
                        enc_connect = self.crypto.encrypt(connect_msg.encode())
                        resp = self._http_post(enc_connect)
                        data = json.loads(self.crypto.decrypt(resp).decode())
                        if data.get("status") == "ok":
                            session_id = data["session"]
                            # Resend buffered data
                            if buffer_out:
                                message = session_id.encode() + b"::" + buffer_out
                                enc_message = self.crypto.encrypt(message)
                                self._http_post(enc_message)
                                buffer_out = b""
                        continue
                    elif plain and plain != b"closed":
                        # Write to local application
                        try:
                            local_conn.sendall(plain)
                        except (BrokenPipeError, ConnectionResetError):
                            break
                    
                    last_send = now
                
                # Small sleep to prevent busy-waiting
                time.sleep(0.001)
                
        except Exception as e:
            print(f"Tunnel error: {e}")
        finally:
            if session_id:
                try:
                    self._send_close(session_id)
                except:
                    pass
            try:
                local_conn.close()
            except:
                pass
    
    def _send_close(self, session_id):
        """Send close message to server."""
        try:
            message = session_id.encode() + b"::CLOSE"
            enc_message = self.crypto.encrypt(message)
            self._http_post(enc_message)
        except:
            pass
    
    def start(self):
        """Start SOCKS5 listener."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(5)
        print(f"SOCKS5 tunnel listening on {self.socks_host}:{self.socks_port}")
        print(f"Tunnel server: {self.server_url}")
        if self.proxies:
            print(f"Outbound proxy: {self.config['outbound_http_proxy']}")
        
        try:
            while self.running:
                conn, addr = server_sock.accept()
                print(f"New SOCKS5 connection from {addr}")
                threading.Thread(
                    target=self.handle_socks_connection, 
                    args=(conn,), 
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            print("\nShutting down...")
            self.running = False
        finally:
            server_sock.close()

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()