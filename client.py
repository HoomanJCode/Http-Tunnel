import json
import socket
import threading
import time
import select
import os
import sys
import logging
import requests
from common import TunnelCrypto, generate_config_wizard, setup_logging, mask_sensitive, PROTO_TCP, PROTO_UDP

class SocksToHttpTunnel:
    def __init__(self, config_path="client_config.json"):
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_config_wizard(config_path, "client"):
                raise RuntimeError("Setup cancelled.")
        
        with open(config_path) as f:
            self.config = json.load(f)
        
        # Setup logging
        self.logger = setup_logging(self.config, "client")
        self.logger.info("Loading configuration...")
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
        self.http_timeout = self.config.get("http_timeout", 5)
        self.reconnect_delay = self.config.get("reconnect_delay", 0.5)
        
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        self.running = True
        self.logger.info("SOCKS5 tunnel client initialized")

    def _http_post(self, body: str, context="unknown") -> str:
        """Send POST request to server."""
        headers = {"Content-Type": "text/plain"}
        proxies = self.proxies if self.proxies else None
        
        self.logger.debug(f"[{context}] POST request: {len(body)} bytes")
        
        try:
            start_time = time.time()
            resp = requests.post(
                self.server_url,
                data=body,
                headers=headers,
                proxies=proxies,
                timeout=self.http_timeout
            )
            elapsed = (time.time() - start_time) * 1000
            resp.raise_for_status()
            self.logger.debug(f"[{context}] Response: {len(resp.text)} bytes in {elapsed:.0f}ms")
            return resp.text
        except requests.exceptions.Timeout:
            self.logger.error(f"[{context}] Timeout after {self.http_timeout}s")
            raise
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"[{context}] Connection error")
            raise
        except Exception as e:
            self.logger.error(f"[{context}] HTTP error: {e}")
            raise
    
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
                self.logger.error(f"[{thread_id}] Incomplete greeting from {client_str}")
                return
            
            ver, nmethods = greeting
            
            if ver != 5:
                self.logger.error(f"[{thread_id}] Invalid SOCKS version: {ver}")
                return
            
            methods = local_conn.recv(nmethods)
            self.logger.debug(f"[{thread_id}] Client methods: {list(methods)}")
            
            # Accept no authentication
            local_conn.sendall(b"\x05\x00")
            
            # Step 2: SOCKS5 request
            request = local_conn.recv(4)
            if len(request) < 4:
                self.logger.error(f"[{thread_id}] Incomplete request from {client_str}")
                return
            
            ver, cmd, rsv, atyp = request
            cmd_names = {1: "CONNECT", 2: "BIND", 3: "UDP ASSOCIATE"}
            atyp_names = {1: "IPv4", 3: "DOMAIN", 4: "IPv6"}
            self.logger.info(f"[{thread_id}] Request: {cmd_names.get(cmd, 'UNKNOWN')} ({atyp_names.get(atyp, 'UNKNOWN')})")
            
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
                self.logger.warning(f"[{thread_id}] IPv6 detected: may not work without IPv6 on server")
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
            self.logger.error(f"[{thread_id}] Handshake timeout with {client_str}")
        except Exception as e:
            self.logger.error(f"[{thread_id}] Error: {e}")
        finally:
            try:
                local_conn.close()
            except:
                pass
            self.logger.info(f"[{thread_id}] Closed: {client_str} -> {target_host}:{target_port}")
    
    def _handle_tcp_connect(self, local_conn, client_addr, target_host, target_port, thread_id):
        """Handle TCP CONNECT through HTTP tunnel."""
        session_id = None
        
        try:
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
                        if len(buffer_out) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError):
                    self.logger.debug(f"[{thread_id}] Local connection reset")
                    return
                
                # Determine if we should send
                should_send = False
                if len(buffer_out) > 0:
                    if len(buffer_out) >= self.max_bytes - 2000 or (now - last_send) >= self.batch_wait:
                        should_send = True
                elif (now - last_send) >= self.heartbeat_interval:
                    should_send = True  # Heartbeat
                
                if should_send:
                    if len(buffer_out) > 0:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                    else:
                        payload = b"HEARTBEAT"
                        self.logger.debug(f"[{thread_id}] Heartbeat")
                    
                    # Send through HTTP tunnel
                    session_message = session_id.encode() + b"::" + payload
                    enc_message = self.crypto.encrypt(session_message)
                    
                    try:
                        request_count += 1
                        resp_text = self._http_post(enc_message, f"{thread_id}-req{request_count}")
                        plain_response = self.crypto.decrypt(resp_text)
                        
                        if plain_response == b"destination_closed":
                            self.logger.info(f"[{thread_id}] Destination closed")
                            return
                        elif plain_response == b"invalid_session":
                            self.logger.error(f"[{thread_id}] Session expired")
                            return
                        elif plain_response and plain_response != b"closed":
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
                self.logger.error(f"[{thread_id}] UDP session failed: {resp_data.get('reason', 'Unknown')}")
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
                            
                            # Forward through HTTP tunnel
                            udp_message = udp_session_id.encode() + b"::UDP:" + data
                            enc_message = self.crypto.encrypt(udp_message)
                            resp_text = self._http_post(enc_message, f"{thread_id}-udp-{packet_count}")
                            plain_response = self.crypto.decrypt(resp_text)
                            
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
    
    def start(self):
        """Start SOCKS5 proxy server."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(50)
        
        self.logger.info(f"SOCKS5 on {self.socks_host}:{self.socks_port}")
        self.logger.info(f"Server: {self.server_url}")
        if self.proxies:
            self.logger.info(f"Proxy: {self.config['outbound_http_proxy']}")
        self.logger.info(f"Max: {self.max_bytes}B, Heartbeat: {self.heartbeat_interval}s, Batch: {self.batch_wait}s")
        self.logger.info(f"Log level: {self.config.get('log_level', 'INFO')}")
        
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