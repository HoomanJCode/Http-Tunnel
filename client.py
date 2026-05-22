import json
import socket
import threading
import time
import select
import os
import sys
import logging
import requests
from common import TunnelCrypto, generate_client_config, setup_logging, PROTO_TCP, PROTO_UDP, compress_data, decompress_data, COMPRESS_ZLIB

class SocksToHttpTunnel:
    def __init__(self, config_path="client_config.json"):
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_client_config(config_path):
                raise RuntimeError("Setup cancelled.")
        
        with open(config_path) as f:
            self.config = json.load(f)
        
        # Client-specific defaults
        self.config.setdefault("max_post_bytes", 5242880)
        self.config.setdefault("http_timeout", 30)
        self.config.setdefault("heartbeat_interval", 1)
        self.config.setdefault("batch_wait", 0.01)
        self.config.setdefault("reconnect_delay", 0.5)
        self.config.setdefault("log_level", "INFO")
        
        # Setup logging
        self.logger = setup_logging(self.config, "client")
        self.logger.info("Loading client configuration...")
        self.logger.debug(f"Server URL: {self.config['server_url']}")
        self.logger.debug(f"Outbound proxy: {self.config.get('outbound_http_proxy', 'none')}")
        
        self.crypto = TunnelCrypto(self.config["encryption_key"])
        self.server_url = self.config["server_url"]
        self.proxies = {}
        if self.config.get("outbound_http_proxy"):
            self.proxies = {
                "http": self.config["outbound_http_proxy"],
                "https": self.config["outbound_http_proxy"]
            }
            self.logger.info(f"Using outbound proxy: {self.config['outbound_http_proxy']}")
        
        self.max_bytes = self.config["max_post_bytes"]
        self.batch_wait = self.config["batch_wait"]
        self.heartbeat_interval = self.config["heartbeat_interval"]
        self.http_timeout = self.config["http_timeout"]
        self.reconnect_delay = self.config["reconnect_delay"]
        
        # Compression settings
        self.compression = self.config.get("compression", True)
        self.compress_method = COMPRESS_ZLIB
        self.compress_threshold = self.config.get("compress_threshold", 100)
        self.logger.debug(f"Compression: {'enabled' if self.compression else 'disabled'}")
        
        # Adaptive heartbeat
        self.min_heartbeat = self.heartbeat_interval
        self.max_heartbeat = 30
        self.current_heartbeat = self.min_heartbeat
        
        # QoS settings
        self.high_priority_ports = [22, 80, 443, 8080]  # SSH, HTTP, HTTPS
        self.low_priority_ports = [21, 25, 110, 143]  # FTP, SMTP, POP, IMAP
        
        # Bypass configuration
        self.bypass_ranges = self.config.get("bypass_ranges", [
            "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
        ])
        self.bypass_local = self.config.get("bypass_local", True)
        self.bypass_private = self.config.get("bypass_private", True)
        
        # Pre-compile bypass networks for performance
        import ipaddress
        self.bypass_networks = []
        for cidr in self.bypass_ranges:
            try:
                self.bypass_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                self.logger.warning(f"Invalid bypass range '{cidr}': {e}")
        
        if self.bypass_private:
            # Add all private network ranges if not already included
            private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            for cidr in private_ranges:
                net = ipaddress.ip_network(cidr, strict=False)
                if net not in self.bypass_networks:
                    self.bypass_networks.append(net)
        
        self.logger.info(f"Loaded {len(self.bypass_networks)} bypass networks")
        
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        self.running = True
        self.logger.info("SOCKS5 tunnel client initialized")
    
    def _http_post(self, body: str, context="unknown") -> str:
        """Send POST request to server with connection pooling."""
        headers = {
            "Content-Type": "text/plain",
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=30, max=100"
        }
        proxies = self.proxies if self.proxies else None
        
        self.logger.debug(f"[{context}] POST: {len(body)}B")
        
        # Use session for connection pooling
        if not hasattr(self, '_session'):
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
                proxies=proxies,
                timeout=self.http_timeout
            )
            elapsed = (time.time() - start_time) * 1000
            resp.raise_for_status()
            self.logger.debug(f"[{context}] Response: {len(resp.text)}B in {elapsed:.0f}ms")
            return resp.text
        except requests.exceptions.Timeout:
            self.logger.error(f"[{context}] Timeout after {self.http_timeout}s")
            # Recreate session on timeout
            if hasattr(self, '_session'):
                self._session.close()
                del self._session
            raise
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"[{context}] Connection error")
            if hasattr(self, '_session'):
                self._session.close()
                del self._session
            raise
        except Exception as e:
            self.logger.error(f"[{context}] HTTP error: {e}")
            raise
    
    def _health_check(self):
        """Quick health check of server."""
        try:
            health_msg = json.dumps({"type": "ping"})
            enc_health = self.crypto.encrypt(health_msg.encode())
            resp = self._http_post(enc_health, "health")
            return True
        except:
            return False
    
    def _should_bypass(self, host):
        """Check if host should bypass the tunnel."""
        import ipaddress
        
        # Always bypass localhost
        if self.bypass_local and host in ["127.0.0.1", "localhost", "::1"]:
            self.logger.debug(f"Bypassing localhost: {host}")
            return True
        
        # Try to check if host is an IP address
        try:
            ip = ipaddress.ip_address(host)
            
            # Check against bypass networks
            for network in self.bypass_networks:
                if ip in network:
                    self.logger.debug(f"Bypassing {host} (matches {network})")
                    return True
        except ValueError:
            # Host is a domain name, try to resolve and check
            try:
                resolved_ips = socket.getaddrinfo(host, None)
                for addr_info in resolved_ips:
                    ip_str = addr_info[4][0]
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        for network in self.bypass_networks:
                            if ip in network:
                                self.logger.debug(f"Bypassing {host} ({ip_str} matches {network})")
                                return True
                    except ValueError:
                        pass
            except socket.gaierror:
                pass
        
        return False
    
    def _handle_direct_connect(self, local_conn, client_addr, target_host, target_port, thread_id):
        """Handle TCP connection directly without tunnel."""
        direct_sock = None
        try:
            # Send success to SOCKS5 client first
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            
            # Create direct connection
            self.logger.info(f"[{thread_id}] Direct connect to {target_host}:{target_port}")
            direct_sock = socket.create_connection((target_host, target_port), timeout=10)
            direct_sock.setblocking(False)
            
            # Simple data relay between local and direct
            local_conn.setblocking(False)
            
            while self.running:
                # Check local -> direct
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            self.logger.info(f"[{thread_id}] Direct connection closed by client")
                            return
                        direct_sock.sendall(chunk)
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError):
                    return
                
                # Check direct -> local
                try:
                    while True:
                        chunk = direct_sock.recv(8192)
                        if not chunk:
                            self.logger.info(f"[{thread_id}] Direct connection closed by remote")
                            return
                        local_conn.sendall(chunk)
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError):
                    return
                
                time.sleep(0.001)
                
        except Exception as e:
            self.logger.error(f"[{thread_id}] Direct connection error: {e}")
        finally:
            if direct_sock:
                try:
                    direct_sock.close()
                except:
                    pass
    
    def _handle_tcp_connect(self, local_conn, client_addr, target_host, target_port, thread_id):
        """Handle TCP CONNECT through HTTP tunnel."""
        session_id = None
        
        try:
            # Check if this connection should bypass the tunnel
            if self._should_bypass(target_host):
                self.logger.info(f"[{thread_id}] Direct connection to {target_host}:{target_port}")
                self._handle_direct_connect(local_conn, client_addr, target_host, target_port, thread_id)
                return
            
            # Determine priority
            priority = "normal"
            original_batch_wait = self.batch_wait
            if target_port in self.high_priority_ports:
                priority = "high"
                self.batch_wait = self.config["batch_wait"] * 0.5  # Faster batching
                self.logger.debug(f"[{thread_id}] High priority: {target_port}")
            elif target_port in self.low_priority_ports:
                priority = "low"
                self.batch_wait = self.config["batch_wait"] * 2  # Slower batching
            
            # Create tunnel session on server first
            self.logger.info(f"[{thread_id}] Creating tunnel to {target_host}:{target_port}")
            connect_msg = json.dumps({
                "type": "connect",
                "host": target_host,
                "port": target_port,
                "proto": PROTO_TCP
            })
            
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect, f"{thread_id}-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                self.logger.error(f"[{thread_id}] Server refused: {resp_data.get('reason', 'Unknown')}")
                local_conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            session_id = resp_data["session"]
            
            # Send success to SOCKS5 client
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            self.logger.info(f"[{thread_id}] Tunnel established: {session_id}")
            
            # Data relay loop
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            total_sent = 0
            total_received = 0
            request_count = 0
            
            # Session resumption buffer
            retry_buffer = b""
            retry_count = 0
            max_retries = 5
            
            while self.running and session_id:
                now = time.time()
                
                # Read from local SOCKS5 client
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            self.logger.info(f"[{thread_id}] Client disconnected")
                            self.logger.info(f"[{thread_id}] Stats: {request_count} req, {total_sent}B sent, {total_received}B recv")
                            # Send close to server
                            close_msg = session_id.encode() + b"::CLOSE"
                            enc_close = self.crypto.encrypt(close_msg)
                            try:
                                self._http_post(enc_close, f"{thread_id}-close")
                            except:
                                pass
                            return
                        buffer_out += chunk
                        retry_buffer = b""  # Clear retry buffer on new data
                        retry_count = 0
                        if len(buffer_out) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError):
                    if retry_count < max_retries:
                        retry_count += 1
                        self.logger.info(f"[{thread_id}] Connection reset, retry {retry_count}/{max_retries}")
                        retry_buffer = buffer_out
                        time.sleep(self.reconnect_delay * retry_count)
                        continue
                    self.logger.debug(f"[{thread_id}] Max retries reached")
                    return
                
                # Determine if we should send
                should_send = False
                if len(buffer_out) > 0:
                    if len(buffer_out) >= self.max_bytes - 2000 or (now - last_send) >= self.batch_wait:
                        should_send = True
                # Adaptive heartbeat calculation
                elif (now - last_send) >= self.current_heartbeat:
                    should_send = True  # Heartbeat
                
                if should_send:
                    if len(buffer_out) > 0:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                        # Reset heartbeat on data send
                        self.current_heartbeat = self.min_heartbeat
                        # Compress payload if enabled
                        if self.compression:
                            try:
                                payload = compress_data(payload, self.compress_method, self.compress_threshold)
                            except Exception as e:
                                self.logger.debug(f"[{thread_id}] Compression failed: {e}")
                    else:
                        payload = b"HEARTBEAT"
                        # Exponential backoff for heartbeats
                        self.current_heartbeat = min(self.current_heartbeat * 1.5, self.max_heartbeat)
                        self.logger.debug(f"[{thread_id}] Heartbeat (next in {self.current_heartbeat:.1f}s)")
                    
                    # Send through HTTP tunnel
                    session_message = session_id.encode() + b"::" + payload
                    enc_message = self.crypto.encrypt(session_message)
                    
                    try:
                        request_count += 1
                        resp_text = self._http_post(enc_message, f"{thread_id}-req{request_count}")
                        plain_response = self.crypto.decrypt(resp_text)
                        
                        # Handle responses
                        if plain_response == b"destination_closed":
                            self.logger.info(f"[{thread_id}] Destination closed")
                            return
                        elif plain_response == b"invalid_session":
                            self.logger.error(f"[{thread_id}] Session expired")
                            return
                        elif plain_response and plain_response != b"closed":
                            # Decompress response if needed
                            if self.compression:
                                try:
                                    plain_response = decompress_data(plain_response)
                                except Exception as e:
                                    self.logger.debug(f"[{thread_id}] Decompression failed: {e}")
                            
                            total_received += len(plain_response)
                            try:
                                local_conn.sendall(plain_response)
                            except (BrokenPipeError, ConnectionResetError, OSError):
                                self.logger.debug(f"[{thread_id}] Local write failed")
                                return
                        
                        total_sent += len(payload)
                        last_send = now
                        
                    except Exception as e:
                        self.logger.error(f"[{thread_id}] Request #{request_count} failed: {e}")
                        time.sleep(self.reconnect_delay)
                        continue
                
                time.sleep(0.001)
                
        except Exception as e:
            self.logger.error(f"[{thread_id}] Tunnel error: {e}")
        finally:
            # Restore original batch wait
            self.batch_wait = self.config["batch_wait"]
            if session_id:
                try:
                    close_msg = session_id.encode() + b"::CLOSE"
                    enc_close = self.crypto.encrypt(close_msg)
                    self._http_post(enc_close, f"{thread_id}-final-close")
                except:
                    pass

    def _handle_udp_associate(self, local_conn, client_addr, target_host, target_port, thread_id):
        """Handle UDP ASSOCIATE command."""
        self.logger.info(f"[{thread_id}] UDP ASSOCIATE to {target_host}:{target_port}")
        
        try:
            # Create UDP session on server
            connect_msg = json.dumps({
                "type": "connect",
                "host": target_host,
                "port": target_port,
                "proto": PROTO_UDP
            })
            
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect, f"{thread_id}-udp-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                self.logger.error(f"[{thread_id}] UDP session failed")
                local_conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            udp_session_id = resp_data["session"]
            self.logger.info(f"[{thread_id}] UDP session: {udp_session_id}")
            
            # Create local UDP socket for relay
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(('127.0.0.1', 0))
            udp_port = udp_sock.getsockname()[1]
            udp_sock.setblocking(False)
            
            # Send SOCKS5 UDP associate response
            response = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + udp_port.to_bytes(2, 'big')
            local_conn.sendall(response)
            self.logger.info(f"[{thread_id}] UDP relay on 127.0.0.1:{udp_port}")
            
            # UDP relay loop
            last_activity = time.time()
            packet_count = 0
            
            while self.running and udp_session_id:
                now = time.time()
                
                # Check for UDP packets from local client
                try:
                    ready = select.select([udp_sock], [], [], 0.05)
                    if ready[0]:
                        data, addr = udp_sock.recvfrom(65536)
                        if data:
                            packet_count += 1
                            self.logger.debug(f"[{thread_id}] UDP #{packet_count}: {len(data)}B")
                            
                            # Compress UDP data if enabled
                            if self.compression and data != b"HEARTBEAT":
                                try:
                                    data = compress_data(data, self.compress_method, self.compress_threshold)
                                except Exception as e:
                                    self.logger.debug(f"[{thread_id}] UDP compression failed: {e}")
                            
                            # Forward through HTTP tunnel
                            udp_message = udp_session_id.encode() + b"::UDP:" + data
                            enc_message = self.crypto.encrypt(udp_message)
                            resp_text = self._http_post(enc_message, f"{thread_id}-udp-{packet_count}")
                            plain_response = self.crypto.decrypt(resp_text)
                            
                            # Decompress response if needed
                            if self.compression and plain_response and plain_response != b"HEARTBEAT":
                                try:
                                    plain_response = decompress_data(plain_response)
                                except Exception as e:
                                    self.logger.debug(f"[{thread_id}] UDP decompression failed: {e}")
                            
                            # Send response back to local client
                            if plain_response and plain_response != b"HEARTBEAT":
                                udp_sock.sendto(plain_response, addr)
                            
                            last_activity = now
                except BlockingIOError:
                    pass
                except Exception as e:
                    self.logger.error(f"[{thread_id}] UDP error: {e}")
                
                # Send heartbeat if idle too long
                if now - last_activity > self.heartbeat_interval:
                    try:
                        heartbeat_msg = udp_session_id.encode() + b"::UDP:HEARTBEAT"
                        enc_heartbeat = self.crypto.encrypt(heartbeat_msg)
                        resp_text = self._http_post(enc_heartbeat, f"{thread_id}-udp-heartbeat")
                        last_activity = now
                    except:
                        pass
                
                # Check if SOCKS5 connection is still alive
                try:
                    ready = select.select([local_conn], [], [], 0.001)
                    if ready[0]:
                        data = local_conn.recv(1)
                        if not data:
                            self.logger.debug(f"[{thread_id}] SOCKS5 connection closed")
                            break
                except BlockingIOError:
                    pass
                except:
                    break
            
            udp_sock.close()
            self.logger.info(f"[{thread_id}] UDP ended: {packet_count} packets")
            
        except Exception as e:
            self.logger.error(f"[{thread_id}] UDP error: {e}")

    def handle_socks_connection(self, local_conn: socket.socket, client_addr):
        """Handle a SOCKS5 client connection."""
        session_id = None
        target_host = None
        target_port = None
        thread_id = threading.current_thread().name
        client_str = f"{client_addr[0]}:{client_addr[1]}"
        
        try:
            self.logger.info(f"[{thread_id}] Connection from {client_str}")
            
            # Step 1: SOCKS5 greeting
            local_conn.settimeout(10)
            greeting = local_conn.recv(2)
            if len(greeting) < 2:
                self.logger.error(f"[{thread_id}] Incomplete greeting")
                return
            
            ver, nmethods = greeting
            
            if ver != 5:
                self.logger.error(f"[{thread_id}] Invalid SOCKS version: {ver}")
                return
            
            methods = local_conn.recv(nmethods)
            self.logger.debug(f"[{thread_id}] Auth methods: {list(methods)}")
            
            # Accept no authentication
            local_conn.sendall(b"\x05\x00")
            
            # Step 2: SOCKS5 request
            request = local_conn.recv(4)
            if len(request) < 4:
                self.logger.error(f"[{thread_id}] Incomplete request")
                return
            
            ver, cmd, rsv, atyp = request
            cmd_names = {1: "CONNECT", 2: "BIND", 3: "UDP ASSOCIATE"}
            atyp_names = {1: "IPv4", 3: "DOMAIN", 4: "IPv6"}
            self.logger.info(f"[{thread_id}] Request: {cmd_names.get(cmd, 'UNKNOWN')}")
            
            # Parse target address
            if atyp == 1:  # IPv4
                addr_bytes = local_conn.recv(4)
                target_host = socket.inet_ntoa(addr_bytes)
            elif atyp == 3:  # Domain name
                length = local_conn.recv(1)[0]
                target_host = local_conn.recv(length).decode()
            elif atyp == 4:  # IPv6
                addr_bytes = local_conn.recv(16)
                target_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                self.logger.warning(f"[{thread_id}] IPv6 may not work without IPv6 on server")
            else:
                self.logger.error(f"[{thread_id}] Unsupported address type: {atyp}")
                local_conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            # Parse port
            port_bytes = local_conn.recv(2)
            target_port = int.from_bytes(port_bytes, 'big')
            self.logger.info(f"[{thread_id}] Target: {target_host}:{target_port}")
            
            # Handle different SOCKS5 commands
            if cmd == 1:  # CONNECT (TCP)
                self._handle_tcp_connect(local_conn, client_addr, target_host, target_port, thread_id)
            elif cmd == 3:  # UDP ASSOCIATE
                self._handle_udp_associate(local_conn, client_addr, target_host, target_port, thread_id)
            else:
                self.logger.error(f"[{thread_id}] Unsupported command: {cmd}")
                local_conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                
        except socket.timeout:
            self.logger.error(f"[{thread_id}] Handshake timeout")
        except Exception as e:
            self.logger.error(f"[{thread_id}] Error: {e}")
        finally:
            try:
                local_conn.close()
            except:
                pass
            self.logger.info(f"[{thread_id}] Closed: {target_host}:{target_port}")

    def start(self):
        """Start SOCKS5 proxy server."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(50)
        
        self.logger.info("=== HTTP Tunnel Client ===")
        self.logger.info(f"SOCKS5: {self.socks_host}:{self.socks_port}")
        self.logger.info(f"Server: {self.server_url}")
        if self.proxies:
            self.logger.info(f"Proxy: {self.config['outbound_http_proxy']}")
        self.logger.info(f"Compression: {'ON' if self.compression else 'OFF'} (threshold: {self.compress_threshold}B)")
        self.logger.info(f"Keep-alive: adaptive {self.min_heartbeat}s-{self.max_heartbeat}s")
        self.logger.info(f"Connection pool: enabled (HTTP keep-alive)")
        self.logger.info(f"QoS: port-based priority")
        self.logger.info(f"Session resumption: enabled (max 5 retries)")
        self.logger.info(f"Health checks: every 15s")
        
        if self.bypass_networks:
            bypass_list = ", ".join([str(n) for n in self.bypass_networks[:3]])
            if len(self.bypass_networks) > 3:
                bypass_list += f" +{len(self.bypass_networks) - 3} more"
            self.logger.info(f"Bypass: {bypass_list}")
        
        # Warm up connection pool
        self.logger.info("Warming up connection pool...")
        try:
            warmup_msg = json.dumps({"type": "ping"})
            enc_warmup = self.crypto.encrypt(warmup_msg.encode())
            for i in range(2):
                try:
                    self._http_post(enc_warmup, f"warmup-{i}")
                    self.logger.debug(f"Warmup {i+1}/2 complete")
                except:
                    pass
                time.sleep(0.1)
        except Exception as e:
            self.logger.warning(f"Warmup failed: {e}")
        
        # Start health check thread
        def health_checker():
            while self.running:
                time.sleep(15)
                if self._health_check():
                    self.logger.debug("Health check: OK")
                else:
                    self.logger.warning("Health check: FAILED")
        
        health_thread = threading.Thread(target=health_checker, daemon=True)
        health_thread.start()
        
        try:
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    self.logger.info(f"Connection from {addr[0]}:{addr[1]}")
                    thread = threading.Thread(
                        target=self.handle_socks_connection,
                        args=(conn, addr),
                        daemon=True,
                        name=f"T{addr[1]}"
                    )
                    thread.start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.running = False
        finally:
            server_sock.close()

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()