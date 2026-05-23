"""HTTP tunnel client - main orchestrator.

Bridges local SOCKS5 proxy to remote HTTP tunnel server.
Handles TCP and UDP connections through HTTP POST requests.

Key optimizations:
- Connection throttling to prevent proxy overload
- Retry with backoff on 502/proxy errors
- Smart compression that skips TLS data
"""

import socket
import time
import threading
import logging
import json
import os

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from http_tunnel.crypto import TunnelCrypto
from http_tunnel.compression import compress_data, decompress_data, COMPRESS_ZLIB
from http_tunnel.protocol import (
    PROTO_TCP, PROTO_UDP, create_connect_message, create_ping_message,
    create_session_message, MSG_CLOSE, MSG_HEARTBEAT, is_tls_data
)
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
        
        # Outbound proxy configuration
        self.proxies = {}
        self._using_proxy = False
        if self.config.get("outbound_http_proxy"):
            proxy_url = self.config["outbound_http_proxy"]
            self.proxies = {"http": proxy_url, "https": proxy_url}
            self._using_proxy = True
            self.logger.info(f"Using outbound proxy: {proxy_url}")
        
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
        
        # Adaptive heartbeat
        self.min_heartbeat = self.heartbeat_interval
        self.max_heartbeat = 30
        self.current_heartbeat = self.min_heartbeat
        
        # QoS ports
        self.high_priority_ports = [22, 80, 443, 8080]
        
        self.running = True
        
        # Connection throttling for proxy
        self._request_semaphore = threading.Semaphore(15)  # Max 15 concurrent HTTP requests
        
        # HTTP session with retry (but not on 502 - we handle that)
        self._setup_http_session()
        
        # Sub-components
        self.direct = DirectConnector(self)
        self.udp = UdpRelay(self)
        
        self.logger.info("SOCKS5 tunnel client initialized")
    
    def _load_config(self, config_path: str) -> bool:
        """Load or create configuration."""
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_client_config(config_path):
                return False
        self.config = load_and_clean_config(config_path, "client")
        return True
    
    def _setup_http_session(self):
        """Create HTTP session with conservative connection pooling."""
        self._session = requests.Session()
        
        # Don't retry on 502 - we handle it ourselves
        retry_strategy = Retry(
            total=1,
            backoff_factor=1.0,
            status_forcelist=[429, 503],
            allowed_methods=["POST"]
        )
        
        # Smaller pool when using proxy to avoid overwhelming it
        if self._using_proxy:
            pool_size = 10
            pool_max = 15
        else:
            pool_size = 20
            pool_max = 30
        
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_max,
            max_retries=retry_strategy,
            pool_block=False
        )
        
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)
    
    def http_post(self, body: str, context: str = "unknown") -> str:
        """Send POST request to tunnel server with throttling.
        
        Uses semaphore to limit concurrent requests when using proxy.
        Handles 502 errors with retry and backoff.
        """
        headers = {
            "Content-Type": "text/plain",
            "Connection": "keep-alive",
        }
        
        # Throttle concurrent requests
        acquired = self._request_semaphore.acquire(timeout=30)
        if not acquired:
            raise Exception("Too many concurrent requests (timeout waiting for slot)")
        
        try:
            max_retries = 5 if self._using_proxy else 2
            
            for attempt in range(max_retries):
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
                    
                    # Check for proxy errors
                    if resp.status_code == 502:
                        self.logger.warning(
                            f"[{context}] 502 from proxy (attempt {attempt+1}/{max_retries})"
                        )
                        if attempt < max_retries - 1:
                            backoff = self.reconnect_delay * (2 ** min(attempt, 4))
                            time.sleep(backoff)
                            continue
                        raise Exception("Proxy returned 502 after retries")
                    
                    resp.raise_for_status()
                    
                    if len(resp.text) > 500:
                        self.logger.debug(f"[{context}] {len(resp.text)}B in {elapsed:.0f}ms")
                    return resp.text
                    
                except requests.exceptions.Timeout:
                    self.logger.warning(
                        f"[{context}] Timeout (attempt {attempt+1}/{max_retries})"
                    )
                    if attempt < max_retries - 1:
                        time.sleep(self.reconnect_delay * (attempt + 1))
                        continue
                    raise
                except requests.exceptions.ConnectionError:
                    self.logger.warning(
                        f"[{context}] Connection error (attempt {attempt+1}/{max_retries})"
                    )
                    if attempt < max_retries - 1:
                        time.sleep(self.reconnect_delay * (attempt + 1))
                        continue
                    raise
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code == 502:
                        continue  # Already handled above
                    raise
        finally:
            self._request_semaphore.release()
    
    def should_bypass(self, host: str) -> bool:
        """Check if host should bypass tunnel (localhost only)."""
        if self.bypass_local and host in ["127.0.0.1", "localhost", "::1"]:
            return True
        return False
    
    def handle_connection(self, conn: socket.socket, target_host: str, 
                         target_port: int, cmd: int, atyp: int):
        """Route SOCKS5 connection to appropriate handler."""
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
            
            # Send SOCKS5 success
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            self.logger.info(f"[{thread_id}] Tunnel: {session_id}")
            
            # Data relay
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            total_sent = 0
            total_received = 0
            request_count = 0
            
            batch_wait = self.batch_wait * (0.5 if target_port in self.high_priority_ports else 1)
            
            while self.running and session_id:
                now = time.time()
                
                # Read from local app
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
                
                # Send decision
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
                        
                        # Compress (skip TLS data)
                        if self.compression and len(payload) > self.compress_threshold:
                            if not is_tls_data(payload):
                                try:
                                    payload = compress_data(payload, COMPRESS_ZLIB, self.compress_threshold)
                                except:
                                    pass
                        self.current_heartbeat = self.min_heartbeat
                    else:
                        payload = MSG_HEARTBEAT
                        self.current_heartbeat = min(self.current_heartbeat * 1.5, self.max_heartbeat)
                    
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
        """Send session close message."""
        try:
            close_msg = create_session_message(session_id, MSG_CLOSE)
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
        pool_info = "10 hosts/15 conns" if self._using_proxy else "20 hosts/30 conns"
        self.logger.info(f"SOCKS5 on {self.socks_host}:{self.socks_port} → {self.server_url}")
        self.logger.info(f"DNS: {self.dns_mode} | Pool: {pool_info} | Max concurrent: 15")
        self.logger.info(f"Use: curl --socks5-hostname 127.0.0.1:{self.socks_port} --ipv4 https://example.com")
        
        # Health checker
        def health_checker():
            while self.running:
                time.sleep(15)
                try:
                    self.health_check()
                except:
                    pass
        
        threading.Thread(target=health_checker, daemon=True).start()
        
        # SOCKS5 server
        socks_server = Socks5Server(self.socks_host, self.socks_port, self.handle_connection)
        socks_server.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.running = False
            socks_server.stop()