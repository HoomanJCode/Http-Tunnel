import json
import socket
import threading
import time
import select
import os
import sys
import requests
from common import TunnelCrypto, generate_config_wizard, PROTO_TCP, PROTO_UDP

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
        self.http_timeout = self.config.get("http_timeout", 5)
        self.reconnect_delay = self.config.get("reconnect_delay", 0.5)
        
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        self.running = True

    def _http_post(self, body: str) -> str:
        """Send POST request to server."""
        headers = {"Content-Type": "text/plain"}
        proxies = self.proxies if self.proxies else None
        
        try:
            resp = requests.post(
                self.server_url,
                data=body,
                headers=headers,
                proxies=proxies,
                timeout=self.http_timeout
            )
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.Timeout:
            print("HTTP timeout")
            raise
        except requests.exceptions.ConnectionError as e:
            print(f"HTTP connection error: {e}")
            raise
        except Exception as e:
            print(f"HTTP error: {e}")
            raise
    
    def handle_socks_connection(self, local_conn: socket.socket, client_addr):
        """Handle a SOCKS5 client connection."""
        session_id = None
        target_host = None
        target_port = None
        
        try:
            print(f"[{client_addr}] SOCKS5 connection started")
            
            # Step 1: SOCKS5 greeting
            local_conn.settimeout(10)
            greeting = local_conn.recv(2)
            if len(greeting) < 2:
                print(f"[{client_addr}] Failed to receive greeting")
                return
            
            ver, nmethods = greeting
            if ver != 5:
                print(f"[{client_addr}] Invalid SOCKS version: {ver}")
                return
            
            methods = local_conn.recv(nmethods)
            print(f"[{client_addr}] SOCKS5 greeting received, methods: {list(methods)}")
            
            # Accept no authentication
            local_conn.sendall(b"\x05\x00")
            
            # Step 2: SOCKS5 request
            request = local_conn.recv(4)
            if len(request) < 4:
                print(f"[{client_addr}] Failed to receive request")
                return
            
            ver, cmd, rsv, atyp = request
            print(f"[{client_addr}] SOCKS5 request: cmd={cmd}, atyp={atyp}")
            
            # Parse target address
            if atyp == 1:  # IPv4
                addr_bytes = local_conn.recv(4)
                target_host = socket.inet_ntoa(addr_bytes)
            elif atyp == 3:  # Domain name
                length = local_conn.recv(1)[0]
                target_host = local_conn.recv(length).decode()
            elif atyp == 4:  # IPv6
                addr_bytes = local_conn.recv(16)
                target_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                print(f"[{client_addr}] Unsupported address type: {atyp}")
                local_conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            # Parse port
            port_bytes = local_conn.recv(2)
            target_port = int.from_bytes(port_bytes, 'big')
            
            print(f"[{client_addr}] Target: {target_host}:{target_port}, cmd={cmd}")
            
            # Handle different SOCKS5 commands
            if cmd == 1:  # CONNECT (TCP)
                self._handle_tcp_connect(local_conn, client_addr, target_host, target_port)
            elif cmd == 3:  # UDP ASSOCIATE
                self._handle_udp_associate(local_conn, client_addr, target_host, target_port)
            else:
                print(f"[{client_addr}] Unsupported command: {cmd}")
                local_conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                
        except socket.timeout:
            print(f"[{client_addr}] Timeout during handshake")
        except Exception as e:
            print(f"[{client_addr}] Error: {e}")
        finally:
            try:
                local_conn.close()
            except:
                pass
            if target_host:
                print(f"[{client_addr}] Connection closed: {target_host}:{target_port}")
    
    def _handle_tcp_connect(self, local_conn, client_addr, target_host, target_port):
        """Handle TCP CONNECT through HTTP tunnel."""
        session_id = None
        
        try:
            # Send success response to SOCKS5 client
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            print(f"[{client_addr}] SOCKS5 success response sent")
            
            # Create tunnel session on server
            print(f"[{client_addr}] Creating tunnel to {target_host}:{target_port}")
            connect_msg = json.dumps({
                "type": "connect",
                "host": target_host,
                "port": target_port,
                "proto": PROTO_TCP
            })
            
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect)
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                print(f"[{client_addr}] Server refused: {resp_data}")
                return
            
            session_id = resp_data["session"]
            print(f"[{client_addr}] Tunnel established: {session_id}")
            
            # Data relay loop
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            
            while self.running and session_id:
                now = time.time()
                
                # Read from local SOCKS5 client
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            print(f"[{client_addr}] Local client disconnected")
                            # Send close to server
                            close_msg = session_id.encode() + b"::CLOSE"
                            enc_close = self.crypto.encrypt(close_msg)
                            try:
                                self._http_post(enc_close)
                            except:
                                pass
                            return
                        buffer_out += chunk
                        if len(buffer_out) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError):
                    print(f"[{client_addr}] Local connection error")
                    return
                
                # Determine if we should send
                should_send = False
                if len(buffer_out) > 0:
                    if len(buffer_out) >= self.max_bytes - 2000 or (now - last_send) >= self.batch_wait:
                        should_send = True
                elif (now - last_send) >= self.heartbeat_interval:
                    should_send = True  # Heartbeat
                
                if should_send:
                    # Prepare payload
                    if len(buffer_out) > 0:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                    else:
                        payload = b"HEARTBEAT"
                    
                    # Send through HTTP tunnel
                    session_message = session_id.encode() + b"::" + payload
                    enc_message = self.crypto.encrypt(session_message)
                    
                    try:
                        resp_text = self._http_post(enc_message)
                        plain_response = self.crypto.decrypt(resp_text)
                        
                        # Handle responses
                        if plain_response == b"destination_closed":
                            print(f"[{client_addr}] Destination closed connection")
                            return
                        elif plain_response == b"invalid_session":
                            print(f"[{client_addr}] Session expired")
                            return
                        elif plain_response and plain_response != b"closed":
                            # Forward to local client
                            try:
                                local_conn.sendall(plain_response)
                            except (BrokenPipeError, ConnectionResetError, OSError):
                                print(f"[{client_addr}] Local write error")
                                return
                        
                        last_send = now
                        
                    except Exception as e:
                        print(f"[{client_addr}] HTTP request failed: {e}")
                        # Continue trying - don't break the loop
                        time.sleep(self.reconnect_delay)
                        continue
                
                # Small sleep to prevent CPU spinning
                time.sleep(0.001)
                
        except Exception as e:
            print(f"[{client_addr}] TCP tunnel error: {e}")
        finally:
            if session_id:
                try:
                    close_msg = session_id.encode() + b"::CLOSE"
                    enc_close = self.crypto.encrypt(close_msg)
                    self._http_post(enc_close)
                except:
                    pass
    
    def _handle_udp_associate(self, local_conn, client_addr, target_host, target_port):
        """Handle UDP ASSOCIATE command."""
        print(f"[{client_addr}] UDP ASSOCIATE request to {target_host}:{target_port}")
        
        try:
            # Create UDP session on server
            connect_msg = json.dumps({
                "type": "connect",
                "host": target_host,
                "port": target_port,
                "proto": PROTO_UDP
            })
            
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect)
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                print(f"[{client_addr}] UDP session failed: {resp_data}")
                local_conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            udp_session_id = resp_data["session"]
            print(f"[{client_addr}] UDP session created: {udp_session_id}")
            
            # Create local UDP socket for relay
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(('127.0.0.1', 0))
            udp_port = udp_sock.getsockname()[1]
            udp_sock.setblocking(False)
            
            # Send SOCKS5 UDP associate response with our UDP port
            response = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + udp_port.to_bytes(2, 'big')
            local_conn.sendall(response)
            print(f"[{client_addr}] UDP relay listening on 127.0.0.1:{udp_port}")
            
            # UDP relay loop
            last_activity = time.time()
            
            while self.running and udp_session_id:
                now = time.time()
                
                # Check for UDP packets from local client
                try:
                    ready = select.select([udp_sock], [], [], 0.05)
                    if ready[0]:
                        data, addr = udp_sock.recvfrom(65536)
                        if data:
                            # Forward through HTTP tunnel
                            udp_message = udp_session_id.encode() + b"::UDP:" + data
                            enc_message = self.crypto.encrypt(udp_message)
                            resp_text = self._http_post(enc_message)
                            plain_response = self.crypto.decrypt(resp_text)
                            
                            # Send response back to local client
                            if plain_response and plain_response != b"HEARTBEAT":
                                udp_sock.sendto(plain_response, addr)
                            
                            last_activity = now
                except BlockingIOError:
                    pass
                except Exception as e:
                    print(f"[{client_addr}] UDP read error: {e}")
                
                # Send heartbeat if idle too long
                if now - last_activity > self.heartbeat_interval:
                    try:
                        heartbeat_msg = udp_session_id.encode() + b"::UDP:HEARTBEAT"
                        enc_heartbeat = self.crypto.encrypt(heartbeat_msg)
                        resp_text = self._http_post(enc_heartbeat)
                        plain_response = self.crypto.decrypt(resp_text)
                        
                        if plain_response and plain_response != b"HEARTBEAT":
                            # Can't send to specific client in UDP without their address
                            pass
                        
                        last_activity = now
                    except:
                        pass
                
                # Check if SOCKS5 connection is still alive
                try:
                    ready = select.select([local_conn], [], [], 0.001)
                    if ready[0]:
                        data = local_conn.recv(1)
                        if not data:
                            print(f"[{client_addr}] SOCKS5 connection closed")
                            break
                except BlockingIOError:
                    pass
                except:
                    break
            
            udp_sock.close()
            
        except Exception as e:
            print(f"[{client_addr}] UDP error: {e}")
    
    def start(self):
        """Start SOCKS5 proxy server."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(50)
        
        print(f"SOCKS5 proxy listening on {self.socks_host}:{self.socks_port}")
        print(f"Tunnel server: {self.server_url}")
        if self.proxies:
            print(f"Outbound proxy: {self.config['outbound_http_proxy']}")
        print(f"Max POST: {self.max_bytes} bytes")
        print(f"Heartbeat: {self.heartbeat_interval}s")
        
        try:
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    print(f"Connection from {addr}")
                    thread = threading.Thread(
                        target=self.handle_socks_connection,
                        args=(conn, addr),
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