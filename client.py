import json
import socket
import threading
import time
import select
import os
import sys
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
        self.session = requests.Session()  # Reuse HTTP connections
        self.session.headers.update({"Content-Type": "text/plain"})

    def _http_post(self, body: str) -> str:
        """Send POST with retry logic."""
        last_error = None
        for attempt in range(3):
            try:
                resp = self.session.post(
                    self.server_url,
                    data=body,
                    proxies=self.proxies if self.proxies else None,
                    timeout=self.http_timeout
                )
                resp.raise_for_status()
                return resp.text
            except requests.exceptions.Timeout as e:
                last_error = e
                print(f"HTTP timeout (attempt {attempt + 1}/3)")
            except requests.exceptions.ConnectionError as e:
                last_error = e
                print(f"HTTP connection error (attempt {attempt + 1}/3): {e}")
            except Exception as e:
                last_error = e
                print(f"HTTP error (attempt {attempt + 1}/3): {e}")
            
            if attempt < 2:
                time.sleep(self.reconnect_delay * (attempt + 1))
        
        raise last_error
    
    def handle_socks_connection(self, local_conn: socket.socket):
        """Handle SOCKS5 connection and tunnel it through HTTP."""
        session_id = None
        target_host = None
        target_port = None
        
        try:
            # SOCKS5 handshake
            local_conn.settimeout(10)
            
            # Greeting
            ver, nmethods = local_conn.recv(2)
            if ver != 5:
                print(f"Invalid SOCKS version: {ver}")
                local_conn.close()
                return
            methods = local_conn.recv(nmethods)
            local_conn.sendall(b"\x05\x00")  # No authentication
            
            # Request
            data = local_conn.recv(4)
            if len(data) < 4:
                local_conn.close()
                return
            ver, cmd, rsv, atyp = data
            if cmd != 1:  # CONNECT only
                print(f"Unsupported SOCKS command: {cmd}")
                # Send error
                local_conn.sendall(b"\x05\x07\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
                local_conn.close()
                return
            
            # Parse target address
            if atyp == 1:  # IPv4
                addr_data = local_conn.recv(4)
                if len(addr_data) < 4:
                    local_conn.close()
                    return
                target_host = socket.inet_ntoa(addr_data)
            elif atyp == 3:  # Domain name
                length_data = local_conn.recv(1)
                if not length_data:
                    local_conn.close()
                    return
                length = length_data[0]
                target_host = local_conn.recv(length).decode()
            else:
                print(f"Unsupported address type: {atyp}")
                local_conn.sendall(b"\x05\x08\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
                local_conn.close()
                return
            
            port_data = local_conn.recv(2)
            if len(port_data) < 2:
                local_conn.close()
                return
            target_port = int.from_bytes(port_data, 'big')
            
            print(f"SOCKS5 connect: {target_host}:{target_port}")
            
            # Send success response immediately
            local_conn.sendall(
                b"\x05\x00\x00\x01" + 
                socket.inet_aton("0.0.0.0") + 
                target_port.to_bytes(2, 'big')
            )
            
            # Establish tunnel with server
            connect_msg = json.dumps({
                "type": "connect",
                "host": target_host,
                "port": target_port
            })
            
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect)
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                print(f"Server refused connection: {resp_data}")
                local_conn.close()
                return
            
            session_id = resp_data["session"]
            print(f"Tunnel established: {session_id} -> {target_host}:{target_port}")
            
            # Data relay loop
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            last_heartbeat_response = time.time()
            
            while self.running and session_id:
                now = time.time()
                
                # Check for heartbeat timeout (no response for 30s)
                if now - last_heartbeat_response > 30:
                    print(f"Session {session_id}: Heartbeat timeout, reconnecting...")
                    break
                
                # Read from local application
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            # Local app closed connection
                            print(f"Session {session_id}: Local app disconnected")
                            self._send_message(session_id, b"CLOSE")
                            local_conn.close()
                            return
                        buffer_out += chunk
                        if len(buffer_out) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    print(f"Session {session_id}: Local connection error: {e}")
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
                    if len(buffer_out) > 0:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                    else:
                        payload = b"HEARTBEAT"
                    
                    try:
                        response = self._send_message(session_id, payload)
                        last_heartbeat_response = time.time()
                        
                        if response == b"destination_closed":
                            print(f"Session {session_id}: Destination closed")
                            try:
                                local_conn.sendall(response)
                            except:
                                pass
                            break
                        elif response == b"invalid_session":
                            print(f"Session {session_id}: Invalid session, reconnecting...")
                            break
                        elif response and response != b"closed":
                            # Forward response to local app
                            try:
                                local_conn.sendall(response)
                            except (BrokenPipeError, ConnectionResetError, OSError):
                                print(f"Session {session_id}: Local write error")
                                break
                        
                        last_send = now
                        
                    except Exception as e:
                        print(f"Session {session_id}: HTTP error: {e}")
                        time.sleep(self.reconnect_delay)
                        continue
                
                # Small sleep to prevent busy-waiting
                time.sleep(0.001)
                
        except Exception as e:
            print(f"Tunnel error for {target_host}:{target_port}: {e}")
        finally:
            if session_id:
                try:
                    self._send_message(session_id, b"CLOSE")
                except:
                    pass
            try:
                local_conn.close()
            except:
                pass
            if target_host:
                print(f"Tunnel closed: {target_host}:{target_port}")
    
    def _send_message(self, session_id, message):
        """Send a session message and return decrypted response."""
        # Handle the CONNECT message separately
        if isinstance(message, dict):
            payload = json.dumps(message).encode()
            enc_message = self.crypto.encrypt(payload)
        else:
            # Regular session message
            session_message = session_id.encode() + b"::" + message
            enc_message = self.crypto.encrypt(session_message)
        
        resp_text = self._http_post(enc_message)
        return self.crypto.decrypt(resp_text)
    
    def start(self):
        """Start SOCKS5 listener."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(10)
        print(f"SOCKS5 tunnel listening on {self.socks_host}:{self.socks_port}")
        print(f"Tunnel server: {self.server_url}")
        if self.proxies:
            print(f"Outbound proxy: {self.config['outbound_http_proxy']}")
        
        try:
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    print(f"New connection from {addr}")
                    thread = threading.Thread(
                        target=self.handle_socks_connection, 
                        args=(conn,), 
                        daemon=True
                    )
                    thread.start()
                except Exception as e:
                    if self.running:
                        print(f"Accept error: {e}")
        except KeyboardInterrupt:
            print("\nShutting down...")
            self.running = False
        finally:
            server_sock.close()

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()