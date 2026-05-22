"""HTTP tunnel client - main orchestrator."""

import socket
import time
import threading
import logging
import json

import requests

from http_tunnel.crypto import TunnelCrypto
from http_tunnel.compression import compress_data, decompress_data, COMPRESS_ZLIB
from http_tunnel.protocol import PROTO_TCP, PROTO_UDP, create_connect_message, create_ping_message
from http_tunnel.config import generate_client_config, load_and_clean_config
from http_tunnel.logging import setup_logging
from http_tunnel.client.socks import Socks5Server
from http_tunnel.client.direct import DirectConnector
from http_tunnel.client.udp import UdpRelay


class SocksToHttpTunnel:
    """Main client that bridges SOCKS5 to HTTP tunnel."""
    
    def __init__(self, config_path: str = "client_config.json"):
        if not self._load_config(config_path):
            raise RuntimeError("Setup cancelled.")
        
        self.logger = setup_logging(self.config, "client")
        self.logger.info("Loading client configuration...")
        
        self.crypto = TunnelCrypto(self.config["encryption_key"])
        self.server_url = self.config["server_url"]
        self.proxies = self._setup_proxies()
        
        self.max_bytes = self.config["max_post_bytes"]
        self.batch_wait = self.config["batch_wait"]
        self.heartbeat_interval = self.config["heartbeat_interval"]
        self.http_timeout = self.config["http_timeout"]
        self.reconnect_delay = self.config["reconnect_delay"]
        
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        self.bypass_local = self.config["bypass_local"]
        self.dns_mode = self.config["dns_mode"]
        self.compression = self.config["compression"]
        self.compress_threshold = 100
        
        self.min_heartbeat = self.heartbeat_interval
        self.max_heartbeat = 30
        self.current_heartbeat = self.min_heartbeat
        self.high_priority_ports = [22, 80, 443, 8080]
        
        self.running = True
        self._session = None
        
        # Components
        self.direct = DirectConnector(self)
        self.udp = UdpRelay(self)
        
        self.logger.info("SOCKS5 tunnel client initialized")
    
    def _load_config(self, config_path: str) -> bool:
        """Load or create configuration."""
        import os
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_client_config(config_path):
                return False
        self.config = load_and_clean_config(config_path, "client")
        return True
    
    def _setup_proxies(self) -> dict:
        """Setup HTTP proxies if configured."""
        if self.config.get("outbound_http_proxy"):
            proxy = self.config["outbound_http_proxy"]
            return {"http": proxy, "https": proxy}
        return {}
    
    def http_post(self, body: str, context: str = "unknown") -> str:
        """Send POST request to server with connection pooling."""
        headers = {
            "Content-Type": "text/plain",
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=30, max=100"
        }
        
        if not self._session:
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
                proxies=self.proxies if self.proxies else None,
                timeout=self.http_timeout
            )
            elapsed = (time.time() - start_time) * 1000
            resp.raise_for_status()
            if len(resp.text) > 200:
                self.logger.debug(f"[{context}] {len(resp.text)}B in {elapsed:.0f}ms")
            return resp.text
        except Exception as e:
            self.logger.error(f"[{context}] HTTP error: {e}")
            if self._session:
                try:
                    self._session.close()
                except:
                    pass
                self._session = None
            raise
    
    def should_bypass(self, host: str) -> bool:
        """Check if host should bypass the tunnel."""
        if self.bypass_local and host in ["127.0.0.1", "localhost", "::1"]:
            return True
        return False
    
    def handle_connection(self, conn: socket.socket, target_host: str, 
                         target_port: int, cmd: int, atyp: int):
        """Route connection to appropriate handler."""
        thread_id = threading.current_thread().name
        
        if cmd == 1 and self.should_bypass(target_host):
            self.direct.handle(conn, target_host, target_port, thread_id)
        elif cmd == 1:
            self._handle_tcp_connect(conn, target_host, target_port, thread_id)
        elif cmd == 3:
            self.udp.handle(conn, target_host, target_port, thread_id)
    
    def _handle_tcp_connect(self, local_conn: socket.socket, target_host: str,
                           target_port: int, thread_id: str):
        """Handle TCP CONNECT through HTTP tunnel."""
        session_id = None
        
        try:
            # Establish tunnel
            connect_msg = create_connect_message(target_host, target_port, PROTO_TCP)
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self.http_post(enc_connect, f"{thread_id}-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                self.logger.error(f"[{thread_id}] Server refused: {resp_data.get('reason')}")
                local_conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            session_id = resp_data["session"]
            
            # Send success to SOCKS client
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            self.logger.info(f"[{thread_id}] Tunnel: {session_id}")
            
            # Data relay loop
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            total_sent = 0
            total_received = 0
            request_count = 0
            
            batch_wait = self.batch_wait * (0.5 if target_port in self.high_priority_ports else 1)
            
            while self.running and session_id:
                now = time.time()
                
                # Read from local
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            self.logger.info(f"[{thread_id}] Closed | {total_sent}B↑ {total_received}B↓")
                            self._send_close(session_id, f"{thread_id}-close")
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
                                payload = compress_data(payload, COMPRESS_ZLIB, self.compress_threshold)
                            except:
                                pass
                        self.current_heartbeat = self.min_heartbeat
                    else:
                        payload = b"HEARTBEAT"
                        self.current_heartbeat = min(self.current_heartbeat * 1.5, self.max_heartbeat)
                    
                    from http_tunnel.protocol import create_session_message
                    session_message = create_session_message(session_id, payload)
                    enc_message = self.crypto.encrypt(session_message)
                    
                    try:
                        request_count += 1
                        resp_text = self.http_post(enc_message, f"{thread_id}-req{request_count}")
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
                self._send_close(session_id, f"{thread_id}-final-close")
    
    def _send_close(self, session_id: str, context: str):
        """Send close message for session."""
        try:
            from http_tunnel.protocol import create_session_message
            close_msg = create_session_message(session_id, b"CLOSE")
            enc_close = self.crypto.encrypt(close_msg)
            self.http_post(enc_close, context)
        except:
            pass
    
    def health_check(self) -> bool:
        """Check server health."""
        try:
            enc_health = self.crypto.encrypt(create_ping_message().encode())
            self.http_post(enc_health, "health")
            return True
        except:
            return False
    
    def start(self):
        """Start the tunnel client."""
        self.logger.info(f"SOCKS5 on {self.socks_host}:{self.socks_port} → {self.server_url}")
        self.logger.info(f"DNS: {self.dns_mode} | Compression: {'ON' if self.compression else 'OFF'}")
        self.logger.info(f"Use: curl --socks5-hostname 127.0.0.1:{self.socks_port} --ipv4 https://example.com")
        
        # Start health checker
        def health_checker():
            while self.running:
                time.sleep(15)
                try:
                    self.health_check()
                except:
                    pass
        
        threading.Thread(target=health_checker, daemon=True).start()
        
        # Start SOCKS5 server
        socks_server = Socks5Server(self.socks_host, self.socks_port, self.handle_connection)
        socks_server.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.running = False
            socks_server.stop()
