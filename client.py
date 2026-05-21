import json
import socket
import threading
import time
import select
import requests
from common import TunnelCrypto, create_connect_message, create_close_message

class SocksToHttpTunnel:
    def __init__(self, config_path="client_config.json"):
        with open(config_path) as f:
            self.config = json.load(f)
        self.crypto = TunnelCrypto(self.config["encryption_key"])
        self.server_url = self.config["server_url"]
        self.proxies = {}
        if self.config.get("outbound_http_proxy"):
            self.proxies = {"http": self.config["outbound_http_proxy"],
                            "https": self.config["outbound_http_proxy"]}
        self.max_bytes = self.config["max_post_bytes"]
        self.batch_wait = self.config["batch_wait"]
        self.heartbeat_interval = self.config["heartbeat_interval"]
        self.socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = self.socks_addr[0]
        self.socks_port = int(self.socks_addr[1])

        self.session_id = None
        self.running = True

    def _http_post(self, body: str) -> str:
        """Send POST and return text response body."""
        resp = requests.post(
            self.server_url,
            data=body,
            headers={"Content-Type": "text/plain"},
            proxies=self.proxies,
            timeout=30
        )
        resp.raise_for_status()
        return resp.text

    def handle_socks_connection(self, local_conn: socket.socket):
        """SOCKS5 handshake, then start the tunnel loop."""
        try:
            # Minimal SOCKS5 handshake (no auth, only CONNECT)
            local_conn.settimeout(10)
            # Greeting
            ver, nmethods = local_conn.recv(2)
            methods = local_conn.recv(nmethods)
            local_conn.sendall(b"\x05\x00")  # no auth

            # Request
            ver, cmd, rsv, atyp = local_conn.recv(4)
            if cmd != 1:  # CONNECT only
                local_conn.close()
                return

            # Parse address
            if atyp == 1:  # IPv4
                addr = socket.inet_ntoa(local_conn.recv(4))
            elif atyp == 3:  # Domain
                length = local_conn.recv(1)[0]
                addr = local_conn.recv(length).decode()
            else:
                local_conn.close()
                return
            port = int.from_bytes(local_conn.recv(2), 'big')

            # Reply success
            local_conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (0).to_bytes(2, 'big'))

            # Connect to remote via HTTP tunnel
            connect_msg = create_connect_message(addr, port)
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect)
            data = self.crypto.decrypt(resp).decode()
            info = json.loads(data)
            if info.get("status") != "ok":
                print("Server refused connection:", info)
                local_conn.close()
                return
            self.session_id = info["session"]

            # Relay loop
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()

            while self.running:
                now = time.time()
                # Read from local app
                try:
                    while True:
                        chunk = local_conn.recv(4096)
                        if not chunk:
                            # EOF from local app -> close tunnel
                            enc_close = self.crypto.encrypt(create_close_message().encode())
                            self._http_post(enc_close)
                            local_conn.close()
                            return
                        buffer_out += chunk
                        if len(buffer_out) >= self.max_bytes - 400:
                            break
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError):
                    break

                # Decide if we must send now
                force_send = (
                    len(buffer_out) > 0 and
                    (len(buffer_out) >= self.max_bytes - 400 or
                     now - last_send >= self.batch_wait)
                )
                # Heartbeat: if buffer empty and last send older than heartbeat, send empty
                heartbeat = (len(buffer_out) == 0 and now - last_send >= self.heartbeat_interval)

                if force_send or heartbeat:
                    # Prepare body
                    if len(buffer_out) > 0:
                        chunk_to_send = buffer_out[:self.max_bytes - 400]
                        buffer_out = buffer_out[self.max_bytes - 400:]
                    else:
                        chunk_to_send = b"HEARTBEAT"  # special marker; server ignores

                    enc_chunk = self.crypto.encrypt(chunk_to_send)
                    try:
                        resp_text = self._http_post(enc_chunk)
                    except Exception as e:
                        print("HTTP POST error:", e)
                        time.sleep(1)
                        continue

                    try:
                        plain = self.crypto.decrypt(resp_text)
                    except Exception:
                        print("Decryption failed, skipping response")
                        continue

                    # Write to local app
                    try:
                        local_conn.sendall(plain)
                    except (BrokenPipeError, ConnectionResetError):
                        break

                    last_send = now

                # Small sleep to avoid busy loop
                time.sleep(0.01)

        except Exception as e:
            print("Tunnel error:", e)
        finally:
            try:
                local_conn.close()
            except:
                pass

    def start(self):
        """Start SOCKS listener."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(5)
        print(f"SOCKS tunnel listening on {self.socks_host}:{self.socks_port}")
        while self.running:
            conn, addr = server_sock.accept()
            threading.Thread(target=self.handle_socks_connection, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()
