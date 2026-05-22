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
from common import (
    TunnelCrypto, generate_client_config, setup_logging, 
    compress_data, decompress_data, COMPRESS_ZLIB, 
    PROTO_TCP, PROTO_UDP, load_and_clean_config
)

class SocksToHttpTunnel:
    def __init__(self, config_path="client_config.json"):
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_client_config(config_path):
                raise RuntimeError("Setup cancelled.")
        
        # Load and clean config
        self.config = load_and_clean_config(config_path, "client")
        
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
        
        self.bypass_local = self.config["bypass_local"]
        self.dns_mode = self.config["dns_mode"]
        self.compression = self.config["compression"]
        self.compress_method = COMPRESS_ZLIB
        self.compress_threshold = 100
        
        self.min_heartbeat = self.heartbeat_interval
        self.max_heartbeat = 30
        self.current_heartbeat = self.min_heartbeat
        
        self.high_priority_ports = [22, 80, 443, 8080]
        
        self.running = True
        self.logger.info("SOCKS5 tunnel client initialized")
    
    # ... rest of the class unchanged from previous version ...
    
    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(50)
        
        self.logger.info(f"SOCKS5 on {self.socks_host}:{self.socks_port} → {self.server_url}")
        self.logger.info(f"DNS: {self.dns_mode} | Compression: {'ON' if self.compression else 'OFF'}")
        self.logger.info(f"Use: curl --socks5-hostname 127.0.0.1:{self.socks_port} --ipv4 https://example.com")
        
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