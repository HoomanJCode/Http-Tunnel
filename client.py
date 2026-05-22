import json
import socket
import threading
import time
import select
import os
import sys
import logging
import ipaddress
import requests
from common import TunnelCrypto, generate_client_config, setup_logging, compress_data, decompress_data, COMPRESS_ZLIB, PROTO_TCP, PROTO_UDP

class SocksToHttpTunnel:
    def __init__(self, config_path="client_config.json"):
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_client_config(config_path):
                raise RuntimeError("Setup cancelled.")
        
        with open(config_path) as f:
            self.config = json.load(f)
        
        # Client-specific defaults
        self.config.setdefault("max_post_bytes", 5242880)
        self.config.setdefault("http_timeout", 30)
        self.config.setdefault("heartbeat_interval", 1)
        self.config.setdefault("batch_wait", 0.01)
        self.config.setdefault("reconnect_delay", 0.5)
        self.config.setdefault("log_level", "INFO")
        self.config.setdefault("compression", True)
        self.config.setdefault("bypass_local", True)
        self.config.setdefault("dns_mode", "server")
        
        # Setup logging
        self.logger = setup_logging(self.config, "client")
        self.logger.info("Loading client configuration...")
        
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
        self.http_timeout = self.config["http_timeout"]
        self.reconnect_delay = self.config["reconnect_delay"]
        
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        self.bypass_local = self.config.get("bypass_local", True)
        self.dns_mode = self.config.get("dns_mode", "server")
        self.compression = self.config.get("compression", True)
        self.compress_method = COMPRESS_ZLIB
        self.compress_threshold = 100
        
        self.min_heartbeat = self.heartbeat_interval
        self.max_heartbeat = 30
        self.current_heartbeat = self.min_heartbeat
        
        self.high_priority_ports = [22, 80, 443, 8080]
        
        self.running = True
        self.logger.info("SOCKS5 tunnel client initialized")

    def _http_post(self, body: str, context="unknown") -> str:
        headers = {
            "Content-Type": "text/plain",
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=30, max=100"
        }
        proxies = self.proxies if self.proxies else None
        
        if not hasattr(self, '_session'):
            self._session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=10,
                pool_maxsize=20,
                max_retries=1,
                pool_block=False
            )
            self._session.mount('http://', adapter)
            self._session.mount('https://', adapter)
        
        try:
            start_time = time.time()
            resp = self._session.post(
                self.server_url,
                data=body,
                headers=headers,
                proxies=proxies,
                timeout=self.http_timeout
            )
            elapsed = (time.time() - start_time) * 1000
            resp.raise_for_status()
            if len(resp.text) > 200:
                self.logger.debug(f"[{context}] Response: {len(resp.text)}B in {elapsed:.0f}ms")
            return resp.text
        except Exception as e:
            self.logger.error(f"[{context}] HTTP error: {e}")
            if hasattr(self, '_session'):
                try:
                    self._session.close()
                except:
                    pass
                del self._session
            raise
    
    def _should_bypass(self, host):
        """Bypass ONLY localhost. Everything else goes through tunnel."""
        if self.bypass_local and host in ["127.0.0.1", "localhost", "::1"]:
            return True
        return False
    
    def handle_socks_connection(self, local_conn: socket.socket, client_addr):
        session_id = None
        target_host = None
        target_port = None
        thread_id = threading.current_thread().name
        
        try:
            local_conn.settimeout(10)
            greeting = local_conn.recv(2)
            if len(greeting) < 2:
                return
            
            ver, nmethods = greeting
            if ver != 5:
                return
            
            methods = local_conn.recv(nmethods)
            local_conn.sendall(b"\x05\x00")
            
            request = local_conn.recv(4)
            if len(request) < 4:
                return
            
            ver, cmd, rsv, atyp = request
            
            if atyp == 1:
                addr_bytes = local_conn.recv(4)
                target_host = socket.inet_ntoa(addr_bytes)
                self.logger.debug(f"[{thread_id}] IPv4: {target_host}")
            elif atyp == 3:
                length = local_conn.recv(1)[0]
                target_host = local_conn.recv(length).decode()
                self.logger.debug(f"[{thread_id}] Domain: {target_host}")
            elif atyp == 4:
                addr_bytes = local_conn.recv(16)
                target_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                local_conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            port_bytes = local_conn.recv(2)
            target_port = int.from_bytes(port_bytes, 'big')
            
            self.logger.info(f"[{thread_id}] {target_host}:{target_port}")
            
            # ONLY bypass localhost
            if self._should_bypass(target_host):
                self.logger.info(f"[{thread_id}] Direct (localhost bypass)")
                self._handle_direct_connect(local_conn, target_host, target_port, thread_id)
                return
            
            if cmd == 1:
                self._handle_tcp_connect(local_conn, target_host, target_port, thread_id)
            elif cmd == 3:
                self._handle_udp_associate(local_conn, target_host, target_port, thread_id)
                
        except socket.timeout:
            self.logger.error(f"[{thread_id}] Timeout")
        except Exception as e:
            self.logger.error(f"[{thread_id}] Error: {e}")
        finally:
            try:
                local_conn.close()
            except:
                pass
    
    def _handle_direct_connect(self, local_conn, target_host, target_port, thread_id):
        direct_sock = None
        try:
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            
            direct_sock = socket.create_connection((target_host, target_port), timeout=10)
            direct_sock.setblocking(False)
            local_conn.setblocking(False)
            
            while self.running:
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            return
                        direct_sock.sendall(chunk)
                except BlockingIOError:
                    pass
                except:
                    return
                
                try:
                    while True:
                        chunk = direct_sock.recv(8192)
                        if not chunk:
                            return
                        local_conn.sendall(chunk)
                except BlockingIOError:
                    pass
                except:
                    return
                
                time.sleep(0.001)
        except Exception as e:
            self.logger.error(f"[{thread_id}] Direct error: {e}")
        finally:
            if direct_sock:
                try:
                    direct_sock.close()
                except:
                    pass
    
    def _handle_tcp_connect(self, local_conn, target_host, target_port, thread_id):
        session_id = None
        
        try:
            # Send to server - server will resolve if it's an IP or domain
            connect_msg = json.dumps({
                "type": "connect",
                "host": target_host,
                "port": target_port,
                "proto": PROTO_TCP
            })
            
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect, f"{thread_id}-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                self.logger.error(f"[{thread_id}] Server refused: {resp_data.get('reason', 'Unknown')}")
                local_conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            session_id = resp_data["session"]
            
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            self.logger.info(f"[{thread_id}] Tunnel: {session_id}")
            
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            total_sent = 0
            total_received = 0
            request_count = 0
            
            if target_port in self.high_priority_ports:
                batch_wait = self.batch_wait * 0.5
            else:
                batch_wait = self.batch_wait
            
            while self.running and session_id:
                now = time.time()
                
                # Read from local
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            self.logger.info(f"[{thread_id}] Local closed | {total_sent}B↑ {total_received}B↓")
                            close_msg = session_id.encode() + b"::CLOSE"
                            enc_close = self.crypto.encrypt(close_msg)
                            try:
                                self._http_post(enc_close, f"{thread_id}-close")
                            except:
                                pass
                            return
                        buffer_out += chunk
                        if len(buffer_out) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except:
                    return
                
                # Determine if we should send
                should_send = False
                if len(buffer_out) > 0:
                    if len(buffer_out) >= self.max_bytes - 2000 or (now - last_send) >= batch_wait:
                        should_send = True
                elif (now - last_send) >= self.current_heartbeat:
                    should_send = True
                
                if should_send:
                    if len(buffer_out) > 0:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                        if self.compression and len(payload) > self.compress_threshold:
                            try:
                                payload = compress_data(payload, self.compress_method, self.compress_threshold)
                            except:
                                pass
                        self.current_heartbeat = self.min_heartbeat
                    else:
                        payload = b"HEARTBEAT"
                        self.current_heartbeat = min(self.current_heartbeat * 1.5, self.max_heartbeat)
                    
                    session_message = session_id.encode() + b"::" + payload
                    enc_message = self.crypto.encrypt(session_message)
                    
                    try:
                        request_count += 1
                        resp_text = self._http_post(enc_message, f"{thread_id}-req{request_count}")
                        plain_response = self.crypto.decrypt(resp_text)
                        
                        if plain_response == b"destination_closed":
                            self.logger.info(f"[{thread_id}] Remote closed")
                            return
                        elif plain_response == b"invalid_session":
                            self.logger.error(f"[{thread_id}] Session expired")
                            return
                        elif plain_response == b"closed":
                            return
                        elif plain_response and len(plain_response) > 0:
                            # Decompress
                            if self.compression and len(plain_response) > 1:
                                try:
                                    decompressed = decompress_data(plain_response)
                                    if decompressed:
                                        plain_response = decompressed
                                except:
                                    pass
                            
                            total_received += len(plain_response)
                            try:
                                local_conn.sendall(plain_response)
                            except:
                                return
                        
                        total_sent += len(payload)
                        last_send = now
                        
                    except Exception as e:
                        self.logger.error(f"[{thread_id}] Req #{request_count}: {e}")
                        time.sleep(self.reconnect_delay)
                        continue
                
                time.sleep(0.001)
                
        except Exception as e:
            self.logger.error(f"[{thread_id}] Tunnel error: {e}")
        finally:
            if session_id:
                try:
                    close_msg = session_id.encode() + b"::CLOSE"
                    enc_close = self.crypto.encrypt(close_msg)
                    self._http_post(enc_close, f"{thread_id}-final-close")
                except:
                    pass
    
    def _handle_udp_associate(self, local_conn, target_host, target_port, thread_id):
        try:
            connect_msg = json.dumps({
                "type": "connect",
                "host": target_host,
                "port": target_port,
                "proto": PROTO_UDP
            })
            
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect, f"{thread_id}-udp-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                local_conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            udp_session_id = resp_data["session"]
            
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(('127.0.0.1', 0))
            udp_port = udp_sock.getsockname()[1]
            udp_sock.setblocking(False)
            
            response = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + udp_port.to_bytes(2, 'big')
            local_conn.sendall(response)
            
            last_activity = time.time()
            
            while self.running and udp_session_id:
                now = time.time()
                
                try:
                    ready = select.select([udp_sock], [], [], 0.05)
                    if ready[0]:
                        data, addr = udp_sock.recvfrom(65536)
                        if data:
                            udp_message = udp_session_id.encode() + b"::UDP:" + data
                            enc_message = self.crypto.encrypt(udp_message)
                            resp_text = self._http_post(enc_message, f"{thread_id}-udp")
                            plain_response = self.crypto.decrypt(resp_text)
                            
                            if plain_response and plain_response != b"HEARTBEAT":
                                udp_sock.sendto(plain_response, addr)
                            
                            last_activity = now
                except BlockingIOError:
                    pass
                
                if now - last_activity > self.heartbeat_interval:
                    try:
                        heartbeat_msg = udp_session_id.encode() + b"::UDP:HEARTBEAT"
                        enc_heartbeat = self.crypto.encrypt(heartbeat_msg)
                        self._http_post(enc_heartbeat, f"{thread_id}-udp-heartbeat")
                        last_activity = now
                    except:
                        pass
                
                try:
                    ready = select.select([local_conn], [], [], 0.001)
                    if ready[0]:
                        data = local_conn.recv(1)
                        if not data:
                            break
                except:
                    break
            
            udp_sock.close()
        except Exception as e:
            self.logger.error(f"[{thread_id}] UDP error: {e}")
    
    def _health_check(self):
        try:
            health_msg = json.dumps({"type": "ping"})
            enc_health = self.crypto.encrypt(health_msg.encode())
            self._http_post(enc_health, "health")
            return True
        except:
            return False
    
    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(50)
        
        self.logger.info(f"SOCKS5 on {self.socks_host}:{self.socks_port} → {self.server_url}")
        self.logger.info(f"DNS: {self.dns_mode} | Compression: {'ON' if self.compression else 'OFF'}")
        self.logger.info(f"Use: curl --socks5-hostname 127.0.0.1:{self.socks_port} --ipv4 https://example.com")
        
        # Health check thread
        def health_checker():
            while self.running:
                time.sleep(15)
                try:
                    self._health_check()
                except:
                    pass
        
        threading.Thread(target=health_checker, daemon=True).start()
        
        try:
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    threading.Thread(
                        target=self.handle_socks_connection,
                        args=(conn, addr),
                        daemon=True,
                        name=f"T{addr[1]}"
                    ).start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept: {e}")
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.running = False
        finally:
            server_sock.close()

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()