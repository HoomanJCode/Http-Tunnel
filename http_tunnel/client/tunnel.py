"""HTTP tunnel client - protocol-aware routing."""

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
from http_tunnel.protocol import (
    PROTO_TCP, PROTO_UDP, create_connect_message,
    create_session_message, MSG_CLOSE, MSG_HEARTBEAT
)
from http_tunnel.config import generate_client_config, load_and_clean_config
from http_tunnel.logging import setup_logging
from http_tunnel.client.socks import Socks5Server
from http_tunnel.client.direct import DirectConnector
from http_tunnel.client.udp import UdpRelay


def detect_protocol(first_bytes: bytes) -> str:
    """Detect protocol from first bytes of connection.
    
    Returns: 'tls', 'http', 'socks5', 'ssh', 'mtproto', 'unknown'
    """
    if not first_bytes:
        return 'unknown'
    b = first_bytes[0]
    if b == 0x16 or b == 0x17:
        return 'tls'
    if b == 0x05:
        return 'socks5'
    if b == 0xef:
        return 'mtproto'
    if first_bytes.startswith(b'GET ') or first_bytes.startswith(b'POST ') or \
       first_bytes.startswith(b'HEAD ') or first_bytes.startswith(b'PUT ') or \
       first_bytes.startswith(b'DELETE ') or first_bytes.startswith(b'CONNECT '):
        return 'http'
    if first_bytes.startswith(b'SSH-'):
        return 'ssh'
    return 'unknown'


class SocksToHttpTunnel:
    """Bridges SOCKS5 to HTTP tunnel with protocol-based routing."""
    
    def __init__(self, config_path: str = "client_config.json"):
        if not self._load_config(config_path):
            raise RuntimeError("Setup cancelled.")
        self.logger = setup_logging(self.config, "client")
        self.crypto = TunnelCrypto(self.config["encryption_key"])
        self.server_url = self.config["server_url"]
        self.running = True
        self.proxies = {}
        self._using_proxy = False
        if self.config.get("outbound_http_proxy"):
            self.proxies = {"http": self.config["outbound_http_proxy"], "https": self.config["outbound_http_proxy"]}
            self._using_proxy = True
        self.http_timeout = self.config["http_timeout"]
        self.heartbeat_interval = self.config["heartbeat_interval"]
        self.batch_wait = self.config["batch_wait"]
        self.reconnect_delay = self.config["reconnect_delay"]
        self.max_bytes = self.config["max_post_bytes"]
        self.bypass_local = self.config["bypass_local"]
        self._setup_bypass_networks()
        # Protocol-based routing
        self.route_tls = self.config.get("route_tls", "tunnel")
        self.route_http = self.config.get("route_http", "tunnel")
        self.route_other = self.config.get("route_other", "tunnel")
        self.high_priority_ports = self.config.get("high_priority_ports", [22, 80, 443, 8080])
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        self.dns_mode = self.config["dns_mode"]
        self._setup_http_session()
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
    
    def _setup_http_session(self):
        self._session = requests.Session()
        # Larger pool for relay proxy to handle browser concurrency
        pool_hosts = 10 if self._using_proxy else 50
        pool_max = 20 if self._using_proxy else 100
        adapter = HTTPAdapter(pool_connections=pool_hosts, pool_maxsize=pool_max, max_retries=0, pool_block=False)
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)
    
    def http_post(self, body: str, context: str = "unknown") -> str:
        headers = {"Content-Type": "text/plain", "Connection": "keep-alive"}
        max_attempts = 2 if self._using_proxy else 3
        for attempt in range(max_attempts):
            try:
                resp = self._session.post(self.server_url, data=body, headers=headers,
                                         proxies=self.proxies if self.proxies else None, timeout=self.http_timeout)
                if resp.status_code == 502 and attempt < max_attempts - 1:
                    time.sleep(self.reconnect_delay * (attempt + 1))
                    continue
                resp.raise_for_status()
                return resp.text
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt < max_attempts - 1:
                    time.sleep(self.reconnect_delay * (attempt + 1))
                    continue
                raise
    
    def _get_route_for_protocol(self, proto: str) -> str:
        """Get routing mode based on detected protocol."""
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
        
        # Reject IPv6 when server has no IPv6 connectivity
        if atyp == 4:
            self.logger.debug(f"[{thread_id}] IPv6 rejected: {target_host} (server has no IPv6)")
            conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")  # Host unreachable
            return
        
        if cmd != 1:
            if cmd == 3:
                self.udp.handle(conn, target_host, target_port, thread_id)
            return
        
        # Peek at first bytes to detect protocol
        conn.setblocking(True)
        conn.settimeout(3)
        try:
            first_bytes = conn.recv(4096, socket.MSG_PEEK)
        except socket.timeout:
            first_bytes = b""
        except:
            first_bytes = b""
        conn.setblocking(True)
        conn.settimeout(10)
        
        proto = detect_protocol(first_bytes)
        route = self._get_route_for_protocol(proto)
        
        self.logger.info(f"[{thread_id}] {proto}:{target_port} -> {route} ({target_host}:{target_port})")
        
        if route == "direct":
            self._handle_direct(conn, target_host, target_port, thread_id)
        elif route == "proxy" and self._using_proxy:
            self._handle_via_proxy(conn, target_host, target_port, thread_id)
        elif self.should_bypass(target_host):
            self.direct.handle(conn, target_host, target_port, thread_id)
        else:
            self._handle_tunnel(conn, target_host, target_port, thread_id)
    
    def _handle_direct(self, local_conn, target_host, target_port, thread_id):
        remote = None
        try:
            local_conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            remote = socket.create_connection((target_host, target_port), timeout=10)
            remote.setblocking(False)
            local_conn.setblocking(False)
            while self.running:
                try:
                    while True:
                        c = local_conn.recv(8192)
                        if not c:
                            return
                        remote.sendall(c)
                except BlockingIOError:
                    pass
                except:
                    return
                try:
                    while True:
                        c = remote.recv(8192)
                        if not c:
                            return
                        local_conn.sendall(c)
                except BlockingIOError:
                    pass
                except:
                    return
                time.sleep(0.001)
        except Exception as e:
            self.logger.error(f"[{thread_id}] Direct error: {e}")
        finally:
            if remote:
                try:
                    remote.close()
                except:
                    pass
    
    def _handle_via_proxy(self, local_conn, target_host, target_port, thread_id):
        remote = None
        try:
            local_conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            proxy_url = self.config["outbound_http_proxy"]
            proxy_host = proxy_url.split("://")[1].split(":")[0] if "://" in proxy_url else proxy_url.split(":")[0]
            proxy_port = int(proxy_url.split(":")[-1]) if ":" in proxy_url.split("://")[-1] else 8080
            remote = socket.create_connection((proxy_host, proxy_port), timeout=10)
            # HTTP CONNECT for non-HTTP protocols
            connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
            remote.sendall(connect_req.encode())
            resp = remote.recv(4096)
            if b"200" not in resp:
                self.logger.error(f"[{thread_id}] Proxy CONNECT failed")
                return
            remote.setblocking(False)
            local_conn.setblocking(False)
            while self.running:
                try:
                    while True:
                        c = local_conn.recv(8192)
                        if not c:
                            return
                        remote.sendall(c)
                except BlockingIOError:
                    pass
                except:
                    return
                try:
                    while True:
                        c = remote.recv(8192)
                        if not c:
                            return
                        local_conn.sendall(c)
                except BlockingIOError:
                    pass
                except:
                    return
                time.sleep(0.001)
        except Exception as e:
            self.logger.error(f"[{thread_id}] Proxy error: {e}")
        finally:
            if remote:
                try:
                    remote.close()
                except:
                    pass
    
    def _handle_tunnel(self, local_conn, target_host, target_port, thread_id):
        session_id = None
        try:
            connect_msg = create_connect_message(target_host, target_port, PROTO_TCP)
            resp = self.http_post(self.crypto.encrypt(connect_msg.encode()), f"{thread_id}-c")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            if resp_data.get("status") != "ok":
                self.logger.error(f"[{thread_id}] Refused: {resp_data.get('reason','?')}")
                local_conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            session_id = resp_data["session"]
            local_conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            self.logger.info(f"[{thread_id}] {session_id} -> {target_host}:{target_port}")
            local_conn.setblocking(False)
            buf = b""
            last = time.time()
            hb = self.heartbeat_interval
            bw = 0 if self._using_proxy else (self.batch_wait * (0.5 if target_port in self.high_priority_ports else 1) if self.batch_wait > 0 else 0)
            while self.running and session_id:
                now = time.time()
                try:
                    while True:
                        c = local_conn.recv(8192)
                        if not c:
                            self.logger.info(f"[{thread_id}] Closed")
                            self._close(session_id)
                            return
                        buf += c
                        if len(buf) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except:
                    return
                send = False
                if len(buf) > 0:
                    if bw == 0 or len(buf) >= self.max_bytes - 2000 or (now - last) >= bw:
                        send = True
                elif (now - last) >= hb:
                    send = True
                if send:
                    payload = buf[:self.max_bytes - 2000] if buf else MSG_HEARTBEAT
                    buf = buf[self.max_bytes - 2000:] if buf else b""
                    hb = self.heartbeat_interval if buf else min(hb * 1.5, 15 if self._using_proxy else 30)
                    try:
                        resp_text = self.http_post(self.crypto.encrypt(create_session_message(session_id, payload)), f"{thread_id}")
                        plain = self.crypto.decrypt(resp_text)
                        if plain in [b"destination_closed", b"invalid_session", b"closed"]:
                            self.logger.info(f"[{thread_id}] {plain.decode()}")
                            return
                        if plain:
                            try:
                                local_conn.sendall(plain)
                            except:
                                return
                        last = now
                    except Exception as e:
                        self.logger.error(f"[{thread_id}] {e}")
                        time.sleep(self.reconnect_delay)
                time.sleep(0.001)
        except Exception as e:
            self.logger.error(f"[{thread_id}] {e}")
        finally:
            if session_id:
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
        self.logger.info(f"TLS: {self.route_tls} | HTTP: {self.route_http} | Other: {self.route_other}")
        self.logger.info(f"DNS: {self.dns_mode}")
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