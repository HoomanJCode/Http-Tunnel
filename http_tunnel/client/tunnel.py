"""HTTP tunnel client - protocol-aware routing with connection lifetime tracking."""

import socket
import time
import threading
import logging
import json
import os
import ipaddress
import random

import requests
from requests.adapters import HTTPAdapter

from http_tunnel.crypto import TunnelCrypto
from http_tunnel.protocol import (
    PROTO_TCP, PROTO_UDP, create_connect_message,
    create_session_message, MSG_CLOSE, MSG_HEARTBEAT
)
from http_tunnel.config import generate_client_config, load_and_clean_config
from http_tunnel.logging import setup_logging
from http_tunnel.client.socks import Socks5Server
from http_tunnel.client.direct import DirectConnector
from http_tunnel.client.udp import UdpRelay


# Suppress noisy urllib3 logs
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
logging.getLogger("urllib3.util.retry").setLevel(logging.WARNING)


def detect_protocol_from_first_byte(first_byte: int) -> str:
    if first_byte == 0x16 or first_byte == 0x17:
        return 'tls'
    if first_byte in (0x47, 0x50, 0x48, 0x43, 0x44, 0x4f, 0x54):
        return 'http'
    return 'other'


def is_websocket_upgrade(data: bytes) -> bool:
    return (b"Upgrade: websocket" in data or 
            b"upgrade: websocket" in data or 
            b"Upgrade: WebSocket" in data)


def is_websocket_established(first_byte: int) -> bool:
    return first_byte in (0x81, 0x82, 0x88, 0x89, 0x8A)


class ConnectionTracker:
    """Tracks HTTP connection lifetimes for debugging."""
    
    def __init__(self, logger):
        self.logger = logger
        self.connections = {}  # id(session) -> {'created': time, 'requests': count, 'last_used': time}
        self.lock = threading.Lock()
        self.total_created = 0
        self.total_closed = 0
        self.lifetimes = []  # Store recent lifetimes for stats
        self.last_report = time.time()
    
    def created(self, session_id):
        with self.lock:
            self.connections[session_id] = {
                'created': time.time(),
                'requests': 0,
                'last_used': time.time()
            }
            self.total_created += 1
    
    def used(self, session_id):
        with self.lock:
            if session_id in self.connections:
                self.connections[session_id]['requests'] += 1
                self.connections[session_id]['last_used'] = time.time()
    
    def closed(self, session_id):
        now = time.time()
        with self.lock:
            if session_id in self.connections:
                lifetime = now - self.connections[session_id]['created']
                requests = self.connections[session_id]['requests']
                self.lifetimes.append(lifetime)
                if len(self.lifetimes) > 100:
                    self.lifetimes.pop(0)
                del self.connections[session_id]
                self.total_closed += 1
        
        # Log with 5% probability for occasional insight
        if random.random() < 0.05:
            self._report()
    
    def _report(self):
        now = time.time()
        with self.lock:
            active = len(self.connections)
            if self.lifetimes:
                avg_life = sum(self.lifetimes) / len(self.lifetimes)
                min_life = min(self.lifetimes)
                max_life = max(self.lifetimes)
            else:
                avg_life = min_life = max_life = 0
            
        self.logger.debug(
            f"[ConnTracker] active={active} created={self.total_created} closed={self.total_closed} "
            f"avg_life={avg_life:.1f}s min={min_life:.1f}s max={max_life:.1f}s"
        )
        self.last_report = now


class HttpSessionPool:
    """Pool of HTTP sessions with connection tracking."""
    
    def __init__(self, proxy_url=None, pool_size=30, tracker=None):
        self._proxy_url = proxy_url
        self._tracker = tracker
        self._pool = []
        self._lock = threading.Lock()
        self._index = 0
        for _ in range(pool_size):
            session = requests.Session()
            adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0, pool_block=False)
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            self._pool.append(session)
    
    def get(self) -> tuple:
        """Returns (session, session_id) for tracking."""
        with self._lock:
            idx = self._index % len(self._pool)
            self._index += 1
            return self._pool[idx], idx
    
    def create_session(self):
        """Create a fresh session (when old one is reset)."""
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0, pool_block=False)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session


class SocksToHttpTunnel:
    """Bridges SOCKS5 to HTTP tunnel with connection lifetime tracking."""
    
    def __init__(self, config_path: str = "client_config.json"):
        if not self._load_config(config_path):
            raise RuntimeError("Setup cancelled.")
        self.logger = setup_logging(self.config, "client")
        self.tracker = ConnectionTracker(self.logger)
        self.crypto = TunnelCrypto(self.config["encryption_key"])
        self.server_url = self.config["server_url"]
        self.running = True
        
        self._using_proxy = False
        self._proxy_url = None
        if self.config.get("outbound_http_proxy"):
            self._proxy_url = self.config["outbound_http_proxy"]
            self._using_proxy = True
        
        self.http_timeout = self.config["http_timeout"]
        self.heartbeat_interval = self.config["heartbeat_interval"]
        self.heartbeat_max = self.config.get("heartbeat_max", 15)
        self.batch_wait = self.config["batch_wait"]
        self.reconnect_delay = self.config["reconnect_delay"]
        self.max_bytes = self.config["max_post_bytes"]
        self.bypass_local = self.config["bypass_local"]
        self._setup_bypass_networks()
        self.route_tls = self.config.get("route_tls", "tunnel")
        self.route_http = self.config.get("route_http", "tunnel")
        self.route_other = self.config.get("route_other", "tunnel")
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        self.dns_mode = self.config["dns_mode"]
        self.recv_chunk = self.config.get("recv_chunk", 65536)
        self.fast_drain_threshold = self.config.get("fast_drain_threshold", 32768)
        self.fast_drain_interval = self.config.get("fast_drain_interval", 0.05)
        self.http_pool_size = self.config.get("http_pool_size", 30)
        
        self._http_pool = HttpSessionPool(proxy_url=self._proxy_url, pool_size=self.http_pool_size, tracker=self.tracker)
        self._thread_sessions = {}  # tid -> (session, session_id)
        self._thread_lock = threading.Lock()
        
        self.direct = DirectConnector(self)
        self.udp = UdpRelay(self)
        self.logger.info("Client ready")
    
    def _load_config(self, config_path: str) -> bool:
        if not os.path.exists(config_path):
            print(f"Config {config_path} not found. Running wizard...")
            if not generate_client_config(config_path):
                return False
        self.config = load_and_clean_config(config_path, "client")
        return True
    
    def _setup_bypass_networks(self):
        self.bypass_networks = []
        for cidr in self.config.get("bypass_ranges", ["127.0.0.0/8"]):
            try:
                self.bypass_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
    
    def _get_session(self) -> tuple:
        """Get or create HTTP session for current thread. Returns (session, session_id)."""
        tid = threading.current_thread().ident
        with self._thread_lock:
            if tid not in self._thread_sessions:
                session, sid = self._http_pool.get()
                self._thread_sessions[tid] = (session, sid)
                self.tracker.created(sid)
            return self._thread_sessions[tid]
    
    def _replace_session(self):
        """Replace the current thread's session (called when connection is reset)."""
        tid = threading.current_thread().ident
        with self._thread_lock:
            if tid in self._thread_sessions:
                old_session, old_sid = self._thread_sessions[tid]
                self.tracker.closed(old_sid)
            new_session = self._http_pool.create_session()
            new_sid = id(new_session)
            self._thread_sessions[tid] = (new_session, new_sid)
            self.tracker.created(new_sid)
    
    def http_post(self, body: str, context: str = "unknown") -> str:
        session, sid = self._get_session()
        self.tracker.used(sid)
        headers = {"Content-Type": "text/plain", "Connection": "keep-alive"}
        proxies = {"http": self._proxy_url, "https": self._proxy_url} if self._using_proxy else None
        
        for attempt in range(3):
            try:
                resp = session.post(self.server_url, data=body, headers=headers,
                                   proxies=proxies, timeout=self.http_timeout)
                if resp.status_code == 502:
                    if attempt < 2:
                        time.sleep(self.reconnect_delay * (2 ** attempt))
                        continue
                    raise Exception("Server returned 502 after retries")
                resp.raise_for_status()
                return resp.text
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt < 2:
                    time.sleep(self.reconnect_delay * (2 ** attempt))
                    continue
                raise
            except requests.exceptions.ChunkedEncodingError:
                # Connection was reset mid-response - replace session
                self._replace_session()
                if attempt < 2:
                    time.sleep(self.reconnect_delay * (2 ** attempt))
                    continue
                raise
    
    def _get_route_for_protocol(self, proto: str) -> str:
        if proto == 'tls':
            return self.route_tls
        elif proto == 'http':
            return self.route_http
        return self.route_other
    
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
    
    def handle_connection(self, conn: socket.socket, target_host: str, target_port: int, cmd: int, atyp: int):
        thread_id = threading.current_thread().name
        
        if atyp == 4:
            conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        
        if cmd != 1:
            if cmd == 3:
                self.udp.handle(conn, target_host, target_port, thread_id)
            return
        
        conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
        
        conn.setblocking(True)
        conn.settimeout(3)
        try:
            fb = conn.recv(1)
            proto = detect_protocol_from_first_byte(fb[0]) if fb else 'other'
        except:
            proto = 'other'
            fb = b''
        conn.setblocking(True)
        conn.settimeout(10)
        
        route = self._get_route_for_protocol(proto)
        self.logger.info(f"[{thread_id}] {proto}:{target_port} -> {route} ({target_host}:{target_port})")
        
        if route == "direct":
            self._handle_direct(conn, target_host, target_port, thread_id, fb)
        elif route == "proxy" and self._using_proxy:
            self._handle_via_proxy(conn, target_host, target_port, thread_id, fb)
        elif self.should_bypass(target_host):
            self.direct.handle(conn, target_host, target_port, thread_id)
        else:
            self._handle_tunnel(conn, target_host, target_port, thread_id, fb)
    
    def _handle_direct(self, local_conn, target_host, target_port, thread_id, first_byte=b''):
        remote = None
        try:
            remote = socket.create_connection((target_host, target_port), timeout=10)
            if first_byte:
                remote.sendall(first_byte)
            remote.setblocking(False)
            local_conn.setblocking(False)
            while self.running:
                try:
                    while True:
                        c = local_conn.recv(self.recv_chunk)
                        if not c:
                            return
                        remote.sendall(c)
                except BlockingIOError:
                    pass
                except:
                    return
                try:
                    while True:
                        c = remote.recv(self.recv_chunk)
                        if not c:
                            return
                        local_conn.sendall(c)
                except BlockingIOError:
                    pass
                except:
                    return
                time.sleep(0.001)
        except Exception as e:
            self.logger.error(f"[{thread_id}] Direct: {e}")
        finally:
            if remote:
                try:
                    remote.close()
                except:
                    pass
    
    def _handle_via_proxy(self, local_conn, target_host, target_port, thread_id, first_byte=b''):
        remote = None
        try:
            proxy_url = self.config["outbound_http_proxy"]
            proxy_host = proxy_url.split("://")[1].split(":")[0] if "://" in proxy_url else proxy_url.split(":")[0]
            proxy_port = int(proxy_url.split(":")[-1]) if ":" in proxy_url.split("://")[-1] else 8080
            remote = socket.create_connection((proxy_host, proxy_port), timeout=10)
            connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
            remote.sendall(connect_req.encode())
            resp = remote.recv(4096)
            if b"200" not in resp:
                self.logger.error(f"[{thread_id}] Proxy CONNECT failed")
                return
            if first_byte:
                remote.sendall(first_byte)
            remote.setblocking(False)
            local_conn.setblocking(False)
            while self.running:
                try:
                    while True:
                        c = local_conn.recv(self.recv_chunk)
                        if not c:
                            return
                        remote.sendall(c)
                except BlockingIOError:
                    pass
                except:
                    return
                try:
                    while True:
                        c = remote.recv(self.recv_chunk)
                        if not c:
                            return
                        local_conn.sendall(c)
                except BlockingIOError:
                    pass
                except:
                    return
                time.sleep(0.001)
        except Exception as e:
            self.logger.error(f"[{thread_id}] Proxy: {e}")
        finally:
            if remote:
                try:
                    remote.close()
                except:
                    pass
    
    def _handle_tunnel(self, local_conn, target_host, target_port, thread_id, first_byte=b''):
        session_id = None
        is_websocket = False
        fast_drain = False
        close_sent = False
        hb = self.heartbeat_interval
        hb_max = self.heartbeat_max
        bw = self.batch_wait
        
        try:
            connect_msg = create_connect_message(target_host, target_port, PROTO_TCP)
            resp = self.http_post(self.crypto.encrypt(connect_msg.encode()), f"{thread_id}-c")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            if resp_data.get("status") != "ok":
                self.logger.error(f"[{thread_id}] Refused: {resp_data.get('reason','?')}")
                return
            session_id = resp_data["session"]
            
            if first_byte:
                self.http_post(self.crypto.encrypt(create_session_message(session_id, first_byte)), f"{thread_id}-d0")
            
            self.logger.info(f"[{thread_id}] {session_id} -> {target_host}:{target_port}")
            local_conn.setblocking(False)
            buf = b""
            last = time.time()
            
            if first_byte and len(first_byte) > 0 and is_websocket_established(first_byte[0]):
                is_websocket = True
                hb_max = 30
            
            while self.running and session_id:
                now = time.time()
                try:
                    while True:
                        c = local_conn.recv(self.recv_chunk)
                        if not c:
                            self.logger.info(f"[{thread_id}] Closed")
                            if not close_sent:
                                self._close(session_id)
                            return
                        buf += c
                        
                        if not is_websocket and is_websocket_upgrade(buf):
                            is_websocket = True
                            hb_max = 30
                        
                        if len(buf) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except:
                    if not close_sent:
                        self._close(session_id)
                    return
                
                send = False
                if len(buf) > 0:
                    if bw == 0 or len(buf) >= self.max_bytes - 2000 or (now - last) >= bw:
                        send = True
                elif (now - last) >= hb:
                    send = True
                
                if send:
                    if len(buf) > 0:
                        payload = buf[:self.max_bytes - 2000]
                        buf = buf[self.max_bytes - 2000:]
                    else:
                        payload = MSG_HEARTBEAT
                    
                    if not is_websocket:
                        hb = self.heartbeat_interval if buf else min(hb * 1.5, hb_max)
                    
                    try:
                        resp_text = self.http_post(self.crypto.encrypt(create_session_message(session_id, payload)), f"{thread_id}")
                        plain = self.crypto.decrypt(resp_text)
                        
                        if plain in [b"destination_closed", b"invalid_session", b"closed"]:
                            self.logger.info(f"[{thread_id}] {plain.decode()}")
                            close_sent = True
                            return
                        
                        if plain:
                            try:
                                local_conn.sendall(plain)
                            except:
                                return
                            
                            if len(plain) > self.fast_drain_threshold:
                                fast_drain = True
                                hb = self.fast_drain_interval
                                bw = 0
                            else:
                                fast_drain = False
                                hb = self.heartbeat_interval
                                bw = self.batch_wait
                        
                        last = now
                    except Exception as e:
                        self.logger.error(f"[{thread_id}] {e}")
                        time.sleep(self.reconnect_delay)
                time.sleep(0.001)
        except Exception as e:
            self.logger.error(f"[{thread_id}] {e}")
        finally:
            if session_id and not close_sent:
                self._close(session_id)
    
    def _close(self, sid):
        try:
            self.http_post(self.crypto.encrypt(create_session_message(sid, MSG_CLOSE)), "close")
        except:
            pass
    
    def start(self):
        self.logger.info(f"SOCKS5 {self.socks_host}:{self.socks_port} -> {self.server_url}")
        if self._using_proxy:
            self.logger.info(f"Proxy: {self.config['outbound_http_proxy']}")
        self.logger.info(f"TLS:{self.route_tls} HTTP:{self.route_http} Other:{self.route_other}")
        self.logger.info(f"Pool:{self.http_pool_size} HB:{self.heartbeat_interval}s Drain:>{self.fast_drain_threshold}B")
        self.logger.info(f"curl --socks5-hostname 127.0.0.1:{self.socks_port} --ipv4 https://example.com")
        s = Socks5Server(self.socks_host, self.socks_port, self.handle_connection)
        s.start()
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.running = False
            s.stop()