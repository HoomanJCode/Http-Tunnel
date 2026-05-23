"""HTTP tunnel client - main orchestrator. Simple, one tunnel per connection."""

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


class SocksToHttpTunnel:
    """Main client that bridges SOCKS5 to HTTP tunnel."""
    
    def __init__(self, config_path: str = "client_config.json"):
        if not self._load_config(config_path):
            raise RuntimeError("Setup cancelled.")
        self.logger = setup_logging(self.config, "client")
        self.logger.info("Loading client configuration...")
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
        self.compression = self.config["compression"]
        self.compress_threshold = self.config.get("compress_threshold", 100)
        self.skip_compress_tls = self.config.get("skip_compress_tls", True)
        self.bypass_local = self.config["bypass_local"]
        self._setup_bypass_networks()
        self.high_priority_ports = self.config.get("high_priority_ports", [22, 80, 443, 8080])
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        self.dns_mode = self.config["dns_mode"]
        self._setup_http_session()
        self.direct = DirectConnector(self)
        self.udp = UdpRelay(self)
        self.logger.info("SOCKS5 tunnel client initialized")
    
    def _load_config(self, config_path: str) -> bool:
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
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
        if self._using_proxy:
            pool_hosts = 4
            pool_max = 8
        else:
            pool_hosts = 50
            pool_max = 100
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
            except Exception:
                raise
    
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
        if atyp == 4 and self.dns_mode == "server":
            self.logger.debug(f"[{thread_id}] IPv6 address - may fail if server has no IPv6")
        if cmd == 1 and self.should_bypass(target_host):
            self.direct.handle(conn, target_host, target_port, thread_id)
        elif cmd == 1:
            self._handle_tcp_connect(conn, target_host, target_port, thread_id)
        elif cmd == 3:
            self.udp.handle(conn, target_host, target_port, thread_id)
    
    def _handle_tcp_connect(self, local_conn: socket.socket, target_host: str, target_port: int, thread_id: str):
        session_id = None
        try:
            connect_msg = create_connect_message(target_host, target_port, PROTO_TCP)
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self.http_post(enc_connect, f"{thread_id}-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            if resp_data.get("status") != "ok":
                reason = resp_data.get('reason', 'Unknown')
                if 'Network is unreachable' in reason or 'IPv6' in reason:
                    self.logger.debug(f"[{thread_id}] Server cannot reach {target_host}:{target_port}")
                else:
                    self.logger.error(f"[{thread_id}] Server refused: {reason}")
                local_conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            session_id = resp_data["session"]
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            self.logger.info(f"[{thread_id}] Tunnel: {session_id} -> {target_host}:{target_port}")
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            current_heartbeat = self.heartbeat_interval
            if self._using_proxy:
                batch_wait = 0
            else:
                batch_wait = self.batch_wait * (0.5 if target_port in self.high_priority_ports else 1) if self.batch_wait > 0 else 0
            while self.running and session_id:
                now = time.time()
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            self.logger.info(f"[{thread_id}] Closed")
                            self._send_close(session_id)
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
                        current_heartbeat = min(current_heartbeat * 1.5, 15 if self._using_proxy else 30)
                    session_message = create_session_message(session_id, payload)
                    enc_message = self.crypto.encrypt(session_message)
                    try:
                        resp_text = self.http_post(enc_message, f"{thread_id}")
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
                            # Server sends data uncompressed now, so just decompress if needed
                            if len(plain_response) > 1 and plain_response[0] in [0x00, 0x01]:
                                try:
                                    decompressed = decompress_data(plain_response)
                                    if decompressed:
                                        plain_response = decompressed
                                except:
                                    pass
                            try:
                                local_conn.sendall(plain_response)
                            except:
                                return
                        last_send = now
                    except Exception as e:
                        self.logger.error(f"[{thread_id}] Error: {e}")
                        time.sleep(self.reconnect_delay)
                        continue
                time.sleep(0.001)
        except Exception as e:
            self.logger.error(f"[{thread_id}] Tunnel error: {e}")
        finally:
            if session_id:
                self._send_close(session_id)
    
    def _send_close(self, session_id: str):
        try:
            close_msg = create_session_message(session_id, MSG_CLOSE)
            enc_close = self.crypto.encrypt(close_msg)
            self.http_post(enc_close, "close")
        except:
            pass
    
    def start(self):
        self.logger.info(f"SOCKS5 on {self.socks_host}:{self.socks_port} -> {self.server_url}")
        if self._using_proxy:
            self.logger.info(f"Relay proxy mode: reduced pool, instant send, moderate heartbeat")
        self.logger.info(f"DNS: {self.dns_mode} | Compression: {'ON' if self.compression else 'OFF'}")
        self.logger.info(f"Use: curl --socks5-hostname 127.0.0.1:{self.socks_port} --ipv4 https://example.com")
        socks_server = Socks5Server(self.socks_host, self.socks_port, self.handle_connection)
        socks_server.start()
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.running = False
            socks_server.stop()