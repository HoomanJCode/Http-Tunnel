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
            print(f"Config not found. Running wizard...")
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
        
        self.max_bytes = self.config.get("max_post_bytes", 1048576)
        self.batch_wait = self.config.get("batch_wait", 0.1)
        self.heartbeat_interval = self.config.get("heartbeat_interval", 1.0)
        self.http_timeout = self.config.get("http_timeout", 15)
        
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        self.running = True
        self.http_session = requests.Session()
        self.http_session.headers.update({"Content-Type": "text/plain"})

    def _post(self, data: str) -> str:
        """Simple HTTP POST."""
        resp = self.http_session.post(
            self.server_url,
            data=data,
            proxies=self.proxies if self.proxies else None,
            timeout=self.http_timeout
        )
        return resp.text
    
    def handle_connection(self, local_conn):
        session_id = None
        
        try:
            # SOCKS5 handshake
            local_conn.settimeout(30)
            
            # Greeting
            data = local_conn.recv(256)
            if not data or data[0] != 5:
                local_conn.close()
                return
            nmethods = data[1]
            local_conn.recv(nmethods)
            local_conn.sendall(b"\x05\x00")
            
            # Request
            data = local_conn.recv(256)
            if len(data) < 5:
                local_conn.close()
                return
            
            ver, cmd, rsv, atyp = data[0], data[1], data[2], data[3]
            
            if cmd != 1:  # Only CONNECT
                local_conn.sendall(b"\x05\x07\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
                local_conn.close()
                return
            
            # Parse address
            pos = 4
            if atyp == 1:  # IPv4
                host = socket.inet_ntoa(data[pos:pos+4])
                pos += 4
            elif atyp == 3:  # Domain
                length = data[pos]
                pos += 1
                host = data[pos:pos+length].decode()
                pos += length
            else:
                local_conn.close()
                return
            
            port = int.from_bytes(data[pos:pos+2], 'big')
            
            print(f"CONNECT {host}:{port}")
            
            # Send success
            local_conn.sendall(
                b"\x05\x00\x00\x01" + 
                socket.inet_aton("0.0.0.0") + 
                port.to_bytes(2, 'big')
            )
            
            # Create tunnel
            connect_msg = json.dumps({"type": "connect", "host": host, "port": port})
            enc = self.crypto.encrypt(connect_msg.encode())
            resp = self._post(enc)
            result = json.loads(self.crypto.decrypt(resp).decode())
            
            if result.get("status") != "ok":
                print(f"Failed: {result}")
                local_conn.close()
                return
            
            session_id = result["session"]
            print(f"Session: {session_id}")
            
            # Relay loop
            local_conn.setblocking(False)
            buffer = b""
            last_send = time.time()
            
            while self.running and session_id:
                now = time.time()
                
                # Read from local
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            print(f"Local closed")
                            # Send close
                            msg = session_id.encode() + b"::CLOSE"
                            self._post(self.crypto.encrypt(msg))
                            local_conn.close()
                            return
                        buffer += chunk
                except BlockingIOError:
                    pass
                except:
                    break
                
                # Determine if we should send
                should_send = (
                    len(buffer) > self.max_bytes - 2000 or
                    (len(buffer) > 0 and now - last_send >= self.batch_wait) or
                    (len(buffer) == 0 and now - last_send >= self.heartbeat_interval)
                )
                
                if should_send:
                    if buffer:
                        payload = buffer[:self.max_bytes - 2000]
                        buffer = buffer[self.max_bytes - 2000:]
                    else:
                        payload = b"HEARTBEAT"
                    
                    try:
                        msg = session_id.encode() + b"::" + payload
                        enc = self.crypto.encrypt(msg)
                        resp = self._post(enc)
                        data = self.crypto.decrypt(resp)
                        
                        if data == b"closed":
                            print(f"Remote closed")
                            local_conn.close()
                            return
                        elif data and data != b"bad_session":
                            try:
                                local_conn.sendall(data)
                            except:
                                break
                        
                        last_send = now
                    except Exception as e:
                        print(f"POST error: {e}")
                        time.sleep(0.5)
                        continue
                
                time.sleep(0.01)
                
        except Exception as e:
            print(f"Error: {e}")
        finally:
            try:
                local_conn.close()
            except:
                pass
    
    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(10)
        print(f"SOCKS5 on {self.socks_host}:{self.socks_port}")
        print(f"Server: {self.server_url}")
        if self.proxies:
            print(f"Proxy: {self.config['outbound_http_proxy']}")
        
        try:
            while self.running:
                conn, addr = server_sock.accept()
                print(f"Connection from {addr}")
                threading.Thread(target=self.handle_connection, args=(conn,), daemon=True).start()
        except KeyboardInterrupt:
            print("\nShutting down...")
            self.running = False
        finally:
            server_sock.close()

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()