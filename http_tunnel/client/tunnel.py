"""HTTP tunnel client - main orchestrator.

Bridges local SOCKS5 proxy to remote HTTP tunnel server.
Features connection pooling to reuse tunnel sessions for same host:port.
All behavior is configurable via client_config.json.
"""

import socket
import time
import threading
import logging
import json
import os
import ipaddress

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
from http_tunnel.client.pool import ConnectionPool


class SocksToHttpTunnel:
    """Main client that bridges SOCKS5 to HTTP tunnel.
    
    Uses connection pooling to reuse tunnel sessions when multiple
    connections go to the same host:port, dramatically reducing
    HTTP requests and server connections.
    """
    
    def __init__(self, config_path: str = "client_config.json"):
        if not self._load_config(config_path):
            raise RuntimeError("Setup cancelled.")
        
        self.logger = setup_logging(self.config, "client")
        self.logger.info("Loading client configuration...")
        
        # Core
        self.crypto = TunnelCrypto(self.config["encryption_key"])
        self.server_url = self.config["server_url"]
        self.running = True
        
        # Proxy
        self.proxies = {}
        self._using_proxy = False
        if self.config.get("outbound_http_proxy"):
            self.proxies = {
                "http": self.config["outbound_http_proxy"],
                "https": self.config["outbound_http_proxy"]
            }
            self._using_proxy = True
        
        # Connection limits
        self.max_concurrent = self.config["max_concurrent_requests"]
        self.max_socks = self.config["max_socks_connections"]
        self.pool_hosts = self.config["connection_pool_hosts"]
        self.pool_max = self.config["connection_pool_max"]
        
        # Timing
        self.http_timeout = self.config["http_timeout"]
        self.heartbeat_interval = self.config["heartbeat_interval"]
        self.heartbeat_max = self.config["heartbeat_max"]
        self.batch_wait = self.config["batch_wait"]
        self.reconnect_delay = self.config["reconnect_delay"]
        
        # Size
        self.max_bytes = self.config["max_post_bytes"]
        
        # Compression
        self.compression = self.config["compression"]
        self.compress_threshold = self.config["compress_threshold"]
        self.skip_compress_tls = self.config["skip_compress_tls"]
        
        # Retry
        self.max_retries = self.config["max_retries"]
        self.retry_backoff = self.config["retry_backoff"]
        
        # Bypass
        self.bypass_local = self.config["bypass_local"]
        self.bypass_ranges = self.config["bypass_ranges"]
        self._setup_bypass_networks()
        
        # QoS
        self.high_priority_ports = self.config["high_priority_ports"]
        
        # SOCKS5
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        # DNS
        self.dns_mode = self.config["dns_mode"]
        
        # Request throttling
        if self.max_concurrent > 0:
            self._request_semaphore = threading.Semaphore(self.max_concurrent)
        else:
            self._request_semaphore = None
        
        # HTTP session
        self._setup_http_session()
        
        # Connection pool for tunnel session reuse
        self.pool = ConnectionPool(
            max_sessions_per_host=3,
            max_total_sessions=50,
            idle_timeout=60
        )
        
        # Pool cleanup thread
        def pool_cleaner():
            while self.running:
                time.sleep(10)
                self.pool.cleanup_idle()
        threading.Thread(target=pool_cleaner, daemon=True).start()
        
        # Components
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
    
    def _setup_bypass_networks(self):
        """Pre-compile bypass networks from CIDR ranges."""
        self.bypass_networks = []
        for cidr in self.bypass_ranges:
            try:
                self.bypass_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                self.logger.warning(f"Invalid bypass range '{cidr}': {e}")
    
    def _setup_http_session(self):
        """Create HTTP session with configurable connection pooling."""
        self._session = requests.Session()
        
        retry_strategy = Retry(
            total=1,
            backoff_factor=1.0,
            status_forcelist=[429, 503],
            allowed_methods=["POST"]
        )
        
        adapter = HTTPAdapter(
            pool_connections=self.pool_hosts,
            pool_maxsize=self.pool_max,
            max_retries=retry_strategy,
            pool_block=False
        )
        
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)
    
    def http_post(self, body: str, context: str = "unknown") -> str:
        """Send POST request with throttling and retry."""
        headers = {
            "Content-Type": "text/plain",
            "Connection": "keep-alive",
        }
        
        if self._request_semaphore:
            acquired = self._request_semaphore.acquire(timeout=self.http_timeout)
            if not acquired:
                raise Exception("Too many concurrent requests (timeout waiting for slot)")
        
        try:
            for attempt in range(self.max_retries):
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
                    
                    if resp.status_code == 502:
                        self.logger.warning(f"[{context}] 502 (attempt {attempt+1}/{self.max_retries})")
                        if attempt < self.max_retries - 1:
                            backoff = self.reconnect_delay * (self.retry_backoff ** min(attempt, 4))
                            time.sleep(backoff)
                            continue
                        raise Exception("Proxy returned 502 after all retries")
                    
                    resp.raise_for_status()
                    
                    if len(resp.text) > 500:
                        self.logger.debug(f"[{context}] {len(resp.text)}B in {elapsed:.0f}ms")
                    return resp.text
                    
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                    self.logger.warning(f"[{context}] {type(e).__name__} (attempt {attempt+1}/{self.max_retries})")
                    if attempt < self.max_retries - 1:
                        time.sleep(self.reconnect_delay * (attempt + 1))
                        continue
                    raise
        finally:
            if self._request_semaphore:
                self._request_semaphore.release()
    
    def should_bypass(self, host: str) -> bool:
        """Check if host should bypass tunnel based on configured ranges."""
        if self.bypass_local and host in ["127.0.0.1", "localhost", "::1"]:
            return True
        
        try:
            ip = ipaddress.ip_address(host)
            for network in self.bypass_networks:
                if ip in network:
                    return True
        except ValueError:
            pass
        
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
        """Handle TCP CONNECT through HTTP tunnel with connection pooling."""
        
        # Try to reuse existing session for this host:port
        def create_new_session(host, port):
            """Create a new tunnel session on server."""
            connect_msg = create_connect_message(host, port, PROTO_TCP)
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self.http_post(enc_connect, f"{thread_id}-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            if resp_data.get("status") == "ok":
                return resp_data["session"]
            return None
        
        session_id, stream_id, is_new = self.pool.get_or_create_session(
            target_host, target_port, create_new_session
        )
        
        if not session_id:
            self.logger.error(f"[{thread_id}] Failed to get session for {target_host}:{target_port}")
            local_conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        
        # Register this stream's socket in the pool session
        session = self.pool.sessions.get(session_id)
        if session:
            session.add_stream(stream_id, local_conn)
        
        if is_new:
            self.logger.info(f"[{thread_id}] New session {session_id} for {target_host}:{target_port}")
        else:
            self.logger.info(f"[{thread_id}] Reusing session {session_id} for {target_host}:{target_port}")
            # Show pool stats periodically
            stats = self.pool.get_stats()
            self.logger.debug(f"Pool: {stats['sessions']} sessions, {stats['streams']} streams, {stats['hosts']} hosts")
        
        try:
            # Send SOCKS5 success
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            
            # Data relay loop
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            total_sent = 0
            total_received = 0
            request_count = 0
            current_heartbeat = self.heartbeat_interval
            
            batch_wait = self.batch_wait * (0.5 if target_port in self.high_priority_ports else 1) if self.batch_wait > 0 else 0
            
            while self.running and session_id:
                now = time.time()
                
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
                
                should_send = False
                if len(buffer_out) > 0:
                    if batch_wait == 0 or len(buffer_out) >= self.max_bytes - 2000 or (now - last_send) >= batch_wait:
                        should_send = True
                elif (now - last_send) >= current_heartbeat:
                    should_send = True
                
                if should_send:
                    if len(buffer_out) > 0:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                        
                        if self.compression and len(payload) > self.compress_threshold:
                            if not self.skip_compress_tls or not is_tls_data(payload):
                                try:
                                    payload = compress_data(payload, COMPRESS_ZLIB, self.compress_threshold)
                                except:
                                    pass
                        current_heartbeat = self.heartbeat_interval
                    else:
                        payload = MSG_HEARTBEAT
                        current_heartbeat = min(current_heartbeat * 1.5, self.heartbeat_max)
                    
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
            self.pool.close_stream(session_id, stream_id)
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
        limit_info = f"Max reqs: {self.max_concurrent}" if self.max_concurrent > 0 else "Unlimited reqs"
        socks_info = f"Max SOCKS: {self.max_socks}" if self.max_socks > 0 else "Unlimited SOCKS"
        batch_info = f"Batch: {self.batch_wait}s" if self.batch_wait > 0 else "Batching: OFF"
        
        self.logger.info(f"SOCKS5 on {self.socks_host}:{self.socks_port} → {self.server_url}")
        self.logger.info(f"DNS: {self.dns_mode} | {limit_info} | {socks_info}")
        self.logger.info(f"Pool: {self.pool_hosts}/{self.pool_max} | {batch_info} | Retries: {self.max_retries}")
        self.logger.info(f"Session reuse: ON (max 3 per host, 50 total)")
        if self.bypass_ranges:
            self.logger.info(f"Bypass: {', '.join(self.bypass_ranges[:3])}" + 
                           (f" +{len(self.bypass_ranges)-3} more" if len(self.bypass_ranges) > 3 else ""))
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
        socks_server = Socks5Server(
            self.socks_host, self.socks_port, 
            self.handle_connection,
            max_connections=self.max_socks
        )
        socks_server.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.running = False
            socks_server.stop()