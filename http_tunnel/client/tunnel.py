"""HTTP tunnel client - main orchestrator with connection reuse.

Multiple browser connections to the same host:port share a single tunnel session.
Data is multiplexed using stream IDs within the session.
"""

import socket
import time
import threading
import logging
import json
import os
import ipaddress
import select

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


class SharedTunnelSession:
    """A tunnel session that can be shared by multiple local connections.
    
    Multiple browser connections to the same host:port share one tunnel.
    Each local connection gets a unique stream_id for multiplexing.
    """
    
    def __init__(self, session_id: str, target_host: str, target_port: int):
        self.session_id = session_id
        self.target_host = target_host
        self.target_port = target_port
        self.streams = {}  # stream_id -> local socket
        self.stream_lock = threading.Lock()
        self.buffer_out = b""
        self.buffer_lock = threading.Lock()
        self.last_send = time.time()
        self.running = True
        self.total_sent = 0
        self.total_received = 0
        self.request_count = 0
    
    def add_stream(self, stream_id: str, local_conn: socket.socket):
        """Add a local connection to this shared session."""
        with self.stream_lock:
            self.streams[stream_id] = local_conn
    
    def remove_stream(self, stream_id: str):
        """Remove a local connection."""
        with self.stream_lock:
            if stream_id in self.streams:
                try:
                    self.streams[stream_id].close()
                except:
                    pass
                del self.streams[stream_id]
    
    def get_stream_count(self) -> int:
        """Get number of active streams."""
        with self.stream_lock:
            return len(self.streams)
    
    def broadcast_to_streams(self, data: bytes):
        """Send data to all streams (for tunnel responses).
        
        Uses stream ID prefix to route data to correct stream.
        Format: stream_id:data
        """
        if b':' not in data:
            return
        
        parts = data.split(b':', 1)
        stream_id = parts[0].decode('ascii', errors='ignore')
        stream_data = parts[1] if len(parts) > 1 else b""
        
        with self.stream_lock:
            if stream_id in self.streams:
                try:
                    self.streams[stream_id].sendall(stream_data)
                except:
                    self.remove_stream(stream_id)
    
    def collect_from_streams(self) -> bytes:
        """Collect data from all streams with their stream IDs.
        
        Returns formatted data: stream_id:data
        """
        result = b""
        with self.stream_lock:
            dead_streams = []
            for stream_id, sock in list(self.streams.items()):
                try:
                    ready = select.select([sock], [], [], 0.001)
                    if ready[0]:
                        chunk = sock.recv(8192)
                        if not chunk:
                            dead_streams.append(stream_id)
                        else:
                            result += stream_id.encode() + b":" + chunk + b"\n"
                except BlockingIOError:
                    pass
                except:
                    dead_streams.append(stream_id)
            
            for stream_id in dead_streams:
                self.remove_stream(stream_id)
        
        return result
    
    def add_to_buffer(self, data: bytes):
        """Add data to the shared output buffer."""
        with self.buffer_lock:
            self.buffer_out += data
    
    def get_buffer(self) -> bytes:
        """Get and clear the output buffer."""
        with self.buffer_lock:
            data = self.buffer_out
            self.buffer_out = b""
            return data


class SocksToHttpTunnel:
    """Main client that bridges SOCKS5 to HTTP tunnel with connection reuse."""
    
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
        
        # Shared sessions (host:port -> SharedTunnelSession)
        self.shared_sessions = {}
        self.sessions_lock = threading.Lock()
        
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
        
        # Throttling
        if self.max_concurrent > 0:
            self._request_semaphore = threading.Semaphore(self.max_concurrent)
        else:
            self._request_semaphore = None
        
        # HTTP session
        self._setup_http_session()
        
        # Components
        self.direct = DirectConnector(self)
        self.udp = UdpRelay(self)
        
        # Session cleanup thread
        threading.Thread(target=self._cleanup_shared_sessions, daemon=True).start()
        
        self.logger.info("SOCKS5 tunnel client initialized (with connection reuse)")
    
    def _load_config(self, config_path: str) -> bool:
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_client_config(config_path):
                return False
        self.config = load_and_clean_config(config_path, "client")
        return True
    
    def _setup_bypass_networks(self):
        self.bypass_networks = []
        for cidr in self.bypass_ranges:
            try:
                self.bypass_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                self.logger.warning(f"Invalid bypass range '{cidr}': {e}")
    
    def _setup_http_session(self):
        self._session = requests.Session()
        retry_strategy = Retry(total=1, backoff_factor=1.0, status_forcelist=[429, 503], allowed_methods=["POST"])
        adapter = HTTPAdapter(pool_connections=self.pool_hosts, pool_maxsize=self.pool_max, max_retries=retry_strategy, pool_block=False)
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)
    
    def _get_or_create_shared_session(self, target_host: str, target_port: int, thread_id: str):
        """Get existing shared session or create a new one for this host:port."""
        key = f"{target_host}:{target_port}"
        
        with self.sessions_lock:
            if key in self.shared_sessions:
                session = self.shared_sessions[key]
                if session.running:
                    self.logger.debug(f"[{thread_id}] Reusing session {session.session_id} ({session.get_stream_count()} streams)")
                    return session, True  # reused
                else:
                    del self.shared_sessions[key]
        
        # Create new tunnel session
        try:
            connect_msg = create_connect_message(target_host, target_port, PROTO_TCP)
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self.http_post(enc_connect, f"{thread_id}-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                return None, False
            
            session_id = resp_data["session"]
            session = SharedTunnelSession(session_id, target_host, target_port)
            
            with self.sessions_lock:
                self.shared_sessions[key] = session
            
            # Start relay thread for this shared session
            threading.Thread(
                target=self._shared_session_relay,
                args=(session, key),
                daemon=True,
                name=f"Shared-{session_id}"
            ).start()
            
            self.logger.info(f"[{thread_id}] New shared session: {session_id}")
            return session, False
            
        except Exception as e:
            self.logger.error(f"[{thread_id}] Failed to create session: {e}")
            return None, False
    
    def _shared_session_relay(self, session: SharedTunnelSession, key: str):
        """Relay loop for a shared tunnel session.
        
        Collects data from all local streams, sends to server,
        receives responses, broadcasts to appropriate streams.
        """
        current_heartbeat = self.heartbeat_interval
        batch_wait = self.batch_wait * 0.5  # Faster for shared sessions
        
        while self.running and session.running and session.get_stream_count() > 0:
            now = time.time()
            
            # Collect data from all local streams
            stream_data = session.collect_from_streams()
            if stream_data:
                session.add_to_buffer(stream_data)
            
            # Decide to send
            buffer = session.get_buffer()
            should_send = False
            
            if len(buffer) > 0:
                if batch_wait == 0 or len(buffer) >= self.max_bytes - 2000 or (now - session.last_send) >= batch_wait:
                    should_send = True
                    session.add_to_buffer(buffer)  # Put back for sending
                    buffer = session.get_buffer()
            elif (now - session.last_send) >= current_heartbeat:
                should_send = True
            
            if should_send:
                if len(buffer) > 0:
                    payload = buffer[:self.max_bytes - 2000]
                    remaining = buffer[self.max_bytes - 2000:]
                    if remaining:
                        session.add_to_buffer(remaining)
                    
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
                
                session_message = create_session_message(session.session_id, payload)
                enc_message = self.crypto.encrypt(session_message)
                
                try:
                    session.request_count += 1
                    resp_text = self.http_post(enc_message, f"Shared-{session.session_id}")
                    plain_response = self.crypto.decrypt(resp_text)
                    
                    if plain_response == b"destination_closed":
                        self.logger.info(f"Shared session {session.session_id}: Remote closed")
                        session.running = False
                        break
                    elif plain_response == b"invalid_session":
                        self.logger.error(f"Shared session {session.session_id}: Expired")
                        session.running = False
                        break
                    elif plain_response and plain_response != b"closed" and len(plain_response) > 0:
                        if self.compression and len(plain_response) > 1:
                            try:
                                decompressed = decompress_data(plain_response)
                                if decompressed:
                                    plain_response = decompressed
                            except:
                                pass
                        
                        # Parse and route to correct stream
                        for line in plain_response.split(b'\n'):
                            if line:
                                session.broadcast_to_streams(line)
                    
                    session.total_sent += len(payload)
                    session.last_send = now
                    
                except Exception as e:
                    self.logger.error(f"Shared session {session.session_id}: {e}")
                    time.sleep(self.reconnect_delay)
                    continue
            
            time.sleep(0.001)
        
        # Cleanup
        with self.sessions_lock:
            if key in self.shared_sessions:
                del self.shared_sessions[key]
        
        # Close server session
        try:
            close_msg = create_session_message(session.session_id, MSG_CLOSE)
            enc_close = self.crypto.encrypt(close_msg)
            self.http_post(enc_close, f"Shared-{session.session_id}-close")
        except:
            pass
        
        self.logger.info(f"Shared session {session.session_id}: Ended ({session.request_count} req)")
    
    def _cleanup_shared_sessions(self):
        """Clean up dead shared sessions."""
        while self.running:
            time.sleep(10)
            with self.sessions_lock:
                dead = [k for k, s in self.shared_sessions.items() if not s.running or s.get_stream_count() == 0]
                for k in dead:
                    self.shared_sessions[k].running = False
                    del self.shared_sessions[k]
    
    def http_post(self, body: str, context: str = "unknown") -> str:
        """Send POST request with throttling."""
        headers = {"Content-Type": "text/plain", "Connection": "keep-alive"}
        
        if self._request_semaphore:
            acquired = self._request_semaphore.acquire(timeout=self.http_timeout)
            if not acquired:
                raise Exception("Too many concurrent requests")
        
        try:
            for attempt in range(self.max_retries):
                try:
                    start_time = time.time()
                    resp = self._session.post(
                        self.server_url, data=body, headers=headers,
                        proxies=self.proxies if self.proxies else None,
                        timeout=self.http_timeout
                    )
                    
                    if resp.status_code == 502:
                        if attempt < self.max_retries - 1:
                            backoff = self.reconnect_delay * (self.retry_backoff ** min(attempt, 4))
                            time.sleep(backoff)
                            continue
                        raise Exception("502 after retries")
                    
                    resp.raise_for_status()
                    return resp.text
                    
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                    if attempt < self.max_retries - 1:
                        time.sleep(self.reconnect_delay * (attempt + 1))
                        continue
                    raise
        finally:
            if self._request_semaphore:
                self._request_semaphore.release()
    
    def should_bypass(self, host: str) -> bool:
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
        """Route SOCKS5 connection - reuse shared session if available."""
        thread_id = threading.current_thread().name
        
        if cmd == 1 and self.should_bypass(target_host):
            self.direct.handle(conn, target_host, target_port, thread_id)
        elif cmd == 1:
            # Try to reuse existing session
            session, reused = self._get_or_create_shared_session(target_host, target_port, thread_id)
            
            if session is None:
                conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            # Send SOCKS5 success
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            conn.sendall(response)
            
            # Add to shared session
            import uuid
            stream_id = str(uuid.uuid4())[:8]
            session.add_stream(stream_id, conn)
            
            self.logger.info(f"[{thread_id}] {'Reused' if reused else 'New'} session {session.session_id} stream {stream_id}")
        elif cmd == 3:
            self.udp.handle(conn, target_host, target_port, thread_id)
    
    def health_check(self) -> bool:
        try:
            enc_health = self.crypto.encrypt(create_ping_message().encode())
            self.http_post(enc_health, "health")
            return True
        except:
            return False
    
    def start(self):
        limit_info = f"Max reqs: {self.max_concurrent}" if self.max_concurrent > 0 else "Unlimited"
        self.logger.info(f"SOCKS5 on {self.socks_host}:{self.socks_port} → {self.server_url}")
        self.logger.info(f"Connection reuse: ON | {limit_info} | DNS: {self.dns_mode}")
        self.logger.info(f"Use: curl --socks5-hostname 127.0.0.1:{self.socks_port} --ipv4 https://example.com")
        
        threading.Thread(target=lambda: self._health_check_loop(), daemon=True).start()
        
        socks_server = Socks5Server(self.socks_host, self.socks_port, self.handle_connection, max_connections=self.max_socks)
        socks_server.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.running = False
            socks_server.stop()
    
    def _health_check_loop(self):
        while self.running:
            time.sleep(15)
            try:
                self.health_check()
            except:
                pass