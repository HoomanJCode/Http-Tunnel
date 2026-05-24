"""HTTP tunnel client - protocol-aware routing with HTTP/1.1 connection pool."""

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


class SocksToHttpTunnel:
    """Bridges SOCKS5 to HTTP tunnel with HTTP/1.1 connection pool."""
    
    def __init__(self, config_path: str = "client_config.json"):
        if not self._load_config(config_path):
            raise RuntimeError("Setup cancelled.")
        self.logger = setup_logging(self.config, "client")
        self.crypto = TunnelCrypto(self.config["encryption_key"])
        self.server_url = self.config["server_url"]
        self.running = True
        
        self._using_proxy = False
        if self.config.get("outbound_http_proxy"):
            self.proxies = {"http": self.config["outbound_http_proxy"], "https": self.config["outbound_http_proxy"]}
            self._using_proxy = True
        else:
            self.proxies = {}
        
        self.http_timeout = self.config["http_timeout"]
        self.heartbeat_interval = self.config["heartbeat_interval"]
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
        self.pool_hosts = self.config.get("pool_hosts", 10)
        self.pool_max = self.config.get("pool_max", 30)
        self.recv_chunk = self.config.get("recv_chunk", 65536)
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
        adapter = HTTPAdapter(pool_connections=self.pool_hosts, pool_maxsize=self.pool_max, max_retries=0, pool_block=False)
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)
    
    def http_post(self, body: str, context: str = "unknown") -> str:
        headers = {"Content-Type": "text/plain", "Connection": "keep-alive"}
        for attempt in range(2):
            try:
                resp = self._session.post(
                    self.server_url, data=body, headers=headers,
                    proxies=self.proxies if self._using_proxy else None,
                    timeout=self.http_timeout
                )
                if resp.status_code == 502 and attempt < 1:
                    time.sleep(self.reconnect_delay)
                    continue
                resp.raise_for_status()
                return resp.text
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt < 1:
                    time.sleep(self.reconnect_delay)
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
        
        try:
            connect_msg = create_connect_message(target_host, target_port, PROTO_TCP)
            resp = self.http_post(self.crypto.encrypt(connect_msg.encode()), f"{thread_id}-c")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            if resp_data.get("status") != "ok":
                self.logger.error(f"[{thread_id}] Refused: {resp_data.get('reason','?')}")
                return
            session_id = resp_data["session"]
            self.logger.info(f"[{thread_id}] {session_id} -> {target_host}:{target_port}")
            local_conn.setblocking(False)
            buf = first_byte if first_byte else b""
            last = time.time()
            hb = self.heartbeat_interval
            hb_max = 15
            bw = self.batch_wait
            
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
                    return
                
                send = False
                if len(buf) > 0:
                    if bw == 0 or len(buf) >= self.max_bytes - 2000 or (now - last) >= bw:
                        send = True
                elif (now - last) >= hb or fast_drain:
                    send = True
                
                if send:
                    payload = buf[:self.max_bytes - 2000] if buf else MSG_HEARTBEAT
                    buf = buf[self.max_bytes - 2000:] if buf else b""
                    if not is_websocket:
                        hb = self.heartbeat_interval if buf else min(hb * 1.5, hb_max)
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
                            
                            # Adaptive draining: if server sent large response,
                            # it probably has more data. Send next request faster.
                            if len(plain) > 32768:
                                fast_drain = True
                                hb = 0.05
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
        self.logger.info(f"Pool: {self.pool_hosts}/{self.pool_max} | TLS:{self.route_tls} HTTP:{self.route_http} Other:{self.route_other}")
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