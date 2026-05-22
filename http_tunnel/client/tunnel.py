"""HTTP tunnel client - main orchestrator.

Bridges local SOCKS5 proxy to remote HTTP tunnel server.
Handles TCP and UDP connections through HTTP POST requests.

Key optimizations for web browsing:
- Connection pool sizing based on expected browser concurrency
- Request retry with backoff on pool exhaustion
- Session reuse with keep-alive
- Smart compression that skips already-encrypted TLS data
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
from http_tunnel.compression import compress_data, decompress_data, COMPRESS_ZLIB, should_compress
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
    """Main client that bridges SOCKS5 to HTTP tunnel.
    
    Creates a local SOCKS5 proxy that applications connect to.
    Each connection is tunneled through HTTP POST to the remote server.
    """
    
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
        
        # Adaptive heartbeat: starts fast, slows down when idle
        self.min_heartbeat = self.heartbeat_interval
        self.max_heartbeat = 30
        self.current_heartbeat = self.min_heartbeat
        
        # QoS: ports that need lower latency
        self.high_priority_ports = [22, 80, 443, 8080]
        
        self.running = True
        
        # HTTP session with connection pooling
        # Pool size matches typical browser concurrency (6-8 per domain)
        self._setup_http_session()
        
        # Sub-components
        self.direct = DirectConnector(self)
        self.udp = UdpRelay(self)
        
        self.logger.info("SOCKS5 tunnel client initialized")
    
    def _load_config(self, config_path: str) -> bool:
        """Load or create configuration file."""
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_client_config(config_path):
                return False
        self.config = load_and_clean_config(config_path, "client")
        return True
    
    def _setup_proxies(self) -> dict:
        """Setup HTTP proxy configuration."""
        if self.config.get("outbound_http_proxy"):
            proxy = self.config["outbound_http_proxy"]
            return {"http": proxy, "https": proxy}
        return {}
    
    def _setup_http_session(self):
        """Create HTTP session with proper connection pooling.
        
        Pool size of 30 handles typical browser concurrency.
        Retry on pool exhaustion with backoff.
        """
        self._session = requests.Session()
        
        # Retry strategy: retry on pool full, connection errors, and 502/503
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"]
        )
        
        adapter = HTTPAdapter(
            pool_connections=30,   # Max different hosts
            pool_maxsize=50,       # Max connections per host
            max_retries=retry_strategy,
            pool_block=False       # Don't block, raise error if pool full
        )
        
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)
    
    def http_post(self, body: str, context: str = "unknown") -> str:
        """Send POST request to tunnel server.
        
        Uses connection pooling for efficiency.
        Retries on transient errors.
        """
        headers = {
            "Content-Type": "text/plain",
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=30, max=100"
        }
        
        max_retries = 3
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
                resp.raise_for_status()
                
                if len(resp.text) > 200:
                    self.logger.debug(f"[{context}] {len(resp.text)}B in {elapsed:.0f}ms")
                return resp.text
                
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 502:
                    self.logger.warning(f"[{context}] 502 Bad Gateway (attempt {attempt+1}/{max_retries})")
                    if attempt < max_retries - 1:
                        time.sleep(self.reconnect_delay * (attempt + 1))
                        continue
                raise
            except requests.exceptions.Timeout:
                self.logger.warning(f"[{context}] Timeout (attempt {attempt+1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(self.reconnect_delay * (attempt + 1))
                    continue
                raise
            except requests.exceptions.ConnectionError:
                self.logger.warning(f"[{context}] Connection error (attempt {attempt+1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(self.reconnect_delay * (attempt + 1))
                    continue
                raise
            except Exception as e:
                self.logger.error(f"[{context}] HTTP error: {e}")
                raise
    
    def should_bypass(self, host: str) -> bool:
        """Check if host should bypass the tunnel (localhost only)."""
        if self.bypass_local and host in ["127.0.0.1", "localhost", "::1"]:
            return True
        return False
    
    def handle_connection(self, conn: socket.socket, target_host: str, 
                         target_port: int, cmd: int, atyp: int):
        """Route incoming SOCKS5 connection to appropriate handler."""
        thread_id = threading.current_thread().name
        
        if cmd == 1 and self.should_bypass(target_host):
            # Direct connection for localhost
            self.direct.handle(conn, target_host, target_port, thread_id)
        elif cmd == 1:
            # TCP tunnel through HTTP
            self._handle_tcp_connect(conn, target_host, target_port, thread_id)
        elif cmd == 3:
            # UDP relay through HTTP
            self.udp.handle(conn, target_host, target_port, thread_id)
    
    # ─── TCP Tunnel Connection ───────────────────────────────────────
    
    def _handle_tcp_connect(self, local_conn: socket.socket, target_host: str,
                           target_port: int, thread_id: str):
        """Handle TCP CONNECT by tunneling through HTTP POST.
        
        Flow:
        1. Send connect request to server
        2. Send SOCKS5 success to local client
        3. Relay data: local → server → destination → server → local
        4. Use batching for efficiency, heartbeats to keep alive
        """
        session_id = None
        
        try:
            # Step 1: Establish tunnel session on server
            connect_msg = create_connect_message(target_host, target_port, PROTO_TCP)
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self.http_post(enc_connect, f"{thread_id}-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                self.logger.error(f"[{thread_id}] Server refused: {resp_data.get('reason')}")
                local_conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            session_id = resp_data["session"]
            
            # Step 2: Send SOCKS5 success response
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            self.logger.info(f"[{thread_id}] Tunnel: {session_id}")
            
            # Step 3: Data relay loop
            local_conn.setblocking(False)
            buffer_out = b""       # Data from local app waiting to send
            last_send = time.time()
            total_sent = 0
            total_received = 0
            request_count = 0
            
            # High priority ports get faster batching
            batch_wait = self.batch_wait * (0.5 if target_port in self.high_priority_ports else 1)
            
            while self.running and session_id:
                now = time.time()
                
                # Read data from local application
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
                
                # Decide whether to send now
                should_send = False
                if len(buffer_out) > 0:
                    # Send if buffer full or batch wait elapsed
                    if len(buffer_out) >= self.max_bytes - 2000 or (now - last_send) >= batch_wait:
                        should_send = True
                elif (now - last_send) >= self.current_heartbeat:
                    # Send heartbeat to keep connection alive
                    should_send = True
                
                if should_send:
                    # Prepare payload
                    if len(buffer_out) > 0:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                        
                        # Compress if beneficial (skip for TLS data)
                        if self.compression and len(payload) > self.compress_threshold:
                            if not is_tls_data(payload):
                                try:
                                    payload = compress_data(payload, COMPRESS_ZLIB, self.compress_threshold)
                                except:
                                    pass
                        
                        self.current_heartbeat = self.min_heartbeat  # Reset on data
                    else:
                        payload = MSG_HEARTBEAT
                        # Slow down heartbeats when idle (exponential backoff)
                        self.current_heartbeat = min(self.current_heartbeat * 1.5, self.max_heartbeat)
                    
                    # Send through HTTP tunnel
                    session_message = create_session_message(session_id, payload)
                    enc_message = self.crypto.encrypt(session_message)
                    
                    try:
                        request_count += 1
                        resp_text = self.http_post(enc_message, f"{thread_id}-req{request_count}")
                        plain_response = self.crypto.decrypt(resp_text)
                        
                        # Handle response types
                        if plain_response == b"destination_closed":
                            self.logger.info(f"[{thread_id}] Remote closed")
                            return
                        elif plain_response == b"invalid_session":
                            self.logger.error(f"[{thread_id}] Session expired")
                            return
                        elif plain_response == b"closed":
                            return
                        elif plain_response and len(plain_response) > 0:
                            # Decompress response if needed
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
                        
                    except requests.exceptions.HTTPError as e:
                        if e.response is not None and e.response.status_code == 502:
                            self.logger.warning(f"[{thread_id}] 502 - retrying...")
                            time.sleep(self.reconnect_delay)
                            continue
                        raise
                    except Exception as e:
                        self.logger.error(f"[{thread_id}] Req #{request_count}: {e}")
                        time.sleep(self.reconnect_delay)
                        continue
                
                time.sleep(0.001)  # Prevent CPU spinning
                
        except Exception as e:
            self.logger.error(f"[{thread_id}] Tunnel error: {e}")
        finally:
            if session_id:
                self._send_close(session_id, f"{thread_id}-final-close")
    
    def _send_close(self, session_id: str, context: str):
        """Send session close message to server."""
        try:
            close_msg = create_session_message(session_id, MSG_CLOSE)
            enc_close = self.crypto.encrypt(close_msg)
            self.http_post(enc_close, context)
        except:
            pass
    
    # ─── Health Check ────────────────────────────────────────────────
    
    def health_check(self) -> bool:
        """Check if tunnel server is reachable."""
        try:
            enc_health = self.crypto.encrypt(create_ping_message().encode())
            self.http_post(enc_health, "health")
            return True
        except:
            return False
    
    # ─── Startup ─────────────────────────────────────────────────────
    
    def start(self):
        """Start the tunnel client.
        
        Starts SOCKS5 proxy server and health check thread.
        """
        self.logger.info(f"SOCKS5 on {self.socks_host}:{self.socks_port} → {self.server_url}")
        self.logger.info(f"DNS: {self.dns_mode} | Compression: {'ON' if self.compression else 'OFF'}")
        self.logger.info(f"Connection pool: 30 hosts / 50 connections")
        self.logger.info(f"Use: curl --socks5-hostname 127.0.0.1:{self.socks_port} --ipv4 https://example.com")
        
        # Background health checker
        def health_checker():
            while self.running:
                time.sleep(15)
                try:
                    self.health_check()
                except:
                    pass
        
        threading.Thread(target=health_checker, daemon=True).start()
        
        # Start SOCKS5 proxy server (blocking)
        socks_server = Socks5Server(self.socks_host, self.socks_port, self.handle_connection)
        socks_server.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.running = False
            socks_server.stop()