import json
import socket
import threading
import time
import select
import os
import sys
import logging
import requests
from common import TunnelCrypto, generate_config_wizard, PROTO_TCP, PROTO_UDP

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class SocksToHttpTunnel:
    def __init__(self, config_path="client_config.json"):
        if not os.path.exists(config_path):
            print(f"Config file {config_path} not found. Running setup wizard...")
            if not generate_config_wizard(config_path, "client"):
                raise RuntimeError("Setup cancelled.")
        
        with open(config_path) as f:
            self.config = json.load(f)
        
        logger.info("Loading configuration...")
        logger.debug(f"Config: {json.dumps(self.config, indent=2)}")
        
        self.crypto = TunnelCrypto(self.config["encryption_key"])
        self.server_url = self.config["server_url"]
        self.proxies = {}
        if self.config.get("outbound_http_proxy"):
            self.proxies = {
                "http": self.config["outbound_http_proxy"],
                "https": self.config["outbound_http_proxy"]
            }
            logger.info(f"Using outbound proxy: {self.config['outbound_http_proxy']}")
        else:
            logger.info("No outbound proxy configured")
        
        self.max_bytes = self.config["max_post_bytes"]
        self.batch_wait = self.config["batch_wait"]
        self.heartbeat_interval = self.config["heartbeat_interval"]
        self.http_timeout = self.config.get("http_timeout", 5)
        self.reconnect_delay = self.config.get("reconnect_delay", 0.5)
        
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        self.running = True
        logger.info("SOCKS5 tunnel client initialized")

    def _http_post(self, body: str, context="unknown") -> str:
        """Send POST request to server with detailed logging."""
        headers = {"Content-Type": "text/plain"}
        proxies = self.proxies if self.proxies else None
        
        logger.debug(f"[{context}] Sending POST: {len(body)} bytes")
        
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
            logger.debug(f"[{context}] Response received: {len(resp.text)} bytes in {elapsed:.0f}ms")
            return resp.text
        except requests.exceptions.Timeout:
            logger.error(f"[{context}] HTTP timeout after {self.http_timeout}s")
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error(f"[{context}] HTTP connection error: {e}")
            raise
        except Exception as e:
            logger.error(f"[{context}] HTTP error: {e}")
            raise
    
    def handle_socks_connection(self, local_conn: socket.socket, client_addr):
        """Handle a SOCKS5 client connection with detailed logging."""
        session_id = None
        target_host = None
        target_port = None
        thread_id = threading.current_thread().name
        
        try:
            logger.info(f"[{thread_id}] New connection from {client_addr}")
            
            # Step 1: SOCKS5 greeting
            local_conn.settimeout(10)
            greeting = local_conn.recv(2)
            if len(greeting) < 2:
                logger.error(f"[{thread_id}] Failed to receive greeting from {client_addr}")
                return
            
            ver, nmethods = greeting
            logger.debug(f"[{thread_id}] SOCKS version: {ver}, methods count: {nmethods}")
            
            if ver != 5:
                logger.error(f"[{thread_id}] Invalid SOCKS version: {ver}")
                return
            
            methods = local_conn.recv(nmethods)
            logger.debug(f"[{thread_id}] Client methods: {list(methods)}")
            
            # Accept no authentication
            local_conn.sendall(b"\x05\x00")
            logger.debug(f"[{thread_id}] Sent: No authentication required")
            
            # Step 2: SOCKS5 request
            request = local_conn.recv(4)
            if len(request) < 4:
                logger.error(f"[{thread_id}] Failed to receive request from {client_addr}")
                return
            
            ver, cmd, rsv, atyp = request
            cmd_names = {1: "CONNECT", 2: "BIND", 3: "UDP ASSOCIATE"}
            atyp_names = {1: "IPv4", 3: "DOMAIN", 4: "IPv6"}
            logger.info(f"[{thread_id}] Request: {cmd_names.get(cmd, 'UNKNOWN')}, address type: {atyp_names.get(atyp, 'UNKNOWN')}")
            
            # Parse target address
            if atyp == 1:  # IPv4
                addr_bytes = local_conn.recv(4)
                target_host = socket.inet_ntoa(addr_bytes)
                logger.debug(f"[{thread_id}] IPv4 address: {target_host}")
            elif atyp == 3:  # Domain name
                length = local_conn.recv(1)[0]
                target_host = local_conn.recv(length).decode()
                logger.debug(f"[{thread_id}] Domain name: {target_host} (length: {length})")
            elif atyp == 4:  # IPv6
                addr_bytes = local_conn.recv(16)
                target_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                logger.warning(f"[{thread_id}] IPv6 address: {target_host} - may not work if server lacks IPv6")
            else:
                logger.error(f"[{thread_id}] Unsupported address type: {atyp}")
                local_conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            # Parse port
            port_bytes = local_conn.recv(2)
            target_port = int.from_bytes(port_bytes, 'big')
            logger.info(f"[{thread_id}] Target: {target_host}:{target_port}")
            
            # Handle different SOCKS5 commands
            if cmd == 1:  # CONNECT (TCP)
                logger.info(f"[{thread_id}] Handling TCP CONNECT")
                self._handle_tcp_connect(local_conn, client_addr, target_host, target_port, thread_id)
            elif cmd == 3:  # UDP ASSOCIATE
                logger.info(f"[{thread_id}] Handling UDP ASSOCIATE")
                self._handle_udp_associate(local_conn, client_addr, target_host, target_port, thread_id)
            else:
                logger.error(f"[{thread_id}] Unsupported command: {cmd}")
                local_conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                
        except socket.timeout:
            logger.error(f"[{thread_id}] Timeout during handshake with {client_addr}")
        except Exception as e:
            logger.error(f"[{thread_id}] Error handling {client_addr}: {e}", exc_info=True)
        finally:
            try:
                local_conn.close()
            except:
                pass
            logger.info(f"[{thread_id}] Connection closed: {client_addr} -> {target_host}:{target_port}")
    
    def _handle_tcp_connect(self, local_conn, client_addr, target_host, target_port, thread_id):
        """Handle TCP CONNECT through HTTP tunnel with detailed logging."""
        session_id = None
        
        try:
            # Create tunnel session on server first
            logger.info(f"[{thread_id}] Creating tunnel to {target_host}:{target_port}")
            connect_msg = json.dumps({
                "type": "connect",
                "host": target_host,
                "port": target_port,
                "proto": PROTO_TCP
            })
            
            logger.debug(f"[{thread_id}] Connect message: {connect_msg}")
            enc_connect = self.crypto.encrypt(connect_msg.encode())
            resp = self._http_post(enc_connect, f"{thread_id}-connect")
            resp_data = json.loads(self.crypto.decrypt(resp).decode())
            
            logger.debug(f"[{thread_id}] Server response: {resp_data}")
            
            if resp_data.get("status") != "ok":
                logger.error(f"[{thread_id}] Server refused connection: {resp_data}")
                # Send error back to SOCKS client
                local_conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            session_id = resp_data["session"]
            
            # Now send success response to SOCKS5 client
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            logger.info(f"[{thread_id}] Tunnel established: {session_id}")
            
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
                            logger.info(f"[{thread_id}] Local client disconnected")
                            logger.info(f"[{thread_id}] Session stats: {request_count} requests, {total_sent} bytes sent, {total_received} bytes received")
                            # Send close to server
                            close_msg = session_id.encode() + b"::CLOSE"
                            enc_close = self.crypto.encrypt(close_msg)
                            try:
                                self._http_post(enc_close, f"{thread_id}-close")
                            except:
                                pass
                            return
                        buffer_out += chunk
                        logger.debug(f"[{thread_id}] Read {len(chunk)} bytes from local, buffer: {len(buffer_out)} bytes")
                        if len(buffer_out) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    logger.error(f"[{thread_id}] Local connection error: {e}")
                    return
                
                # Determine if we should send
                should_send = False
                if len(buffer_out) > 0:
                    if len(buffer_out) >= self.max_bytes - 2000 or (now - last_send) >= self.batch_wait:
                        should_send = True
                elif (now - last_send) >= self.heartbeat_interval:
                    should_send = True  # Heartbeat
                    logger.debug(f"[{thread_id}] Sending heartbeat")
                
                if should_send:
                    # Prepare payload
                    if len(buffer_out) > 0:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                        logger.debug(f"[{thread_id}] Sending {len(payload)} bytes to server")
                    else:
                        payload = b"HEARTBEAT"
                    
                    # Send through HTTP tunnel
                    session_message = session_id.encode() + b"::" + payload
                    enc_message = self.crypto.encrypt(session_message)
                    
                    try:
                        request_count += 1
                        resp_text = self._http_post(enc_message, f"{thread_id}-data-{request_count}")
                        plain_response = self.crypto.decrypt(resp_text)
                        
                        if plain_response == b"destination_closed":
                            logger.info(f"[{thread_id}] Destination closed connection")
                            return
                        elif plain_response == b"invalid_session":
                            logger.error(f"[{thread_id}] Session expired")
                            return
                        elif plain_response and plain_response != b"closed":
                            logger.debug(f"[{thread_id}] Received {len(plain_response)} bytes from server")
                            total_received += len(plain_response)
                            # Forward to local client
                            try:
                                local_conn.sendall(plain_response)
                                logger.debug(f"[{thread_id}] Forwarded {len(plain_response)} bytes to local")
                            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                                logger.error(f"[{thread_id}] Local write error: {e}")
                                return
                        
                        total_sent += len(payload)
                        last_send = now
                        
                    except Exception as e:
                        logger.error(f"[{thread_id}] HTTP request #{request_count} failed: {e}")
                        time.sleep(self.reconnect_delay)
                        continue
                
                # Small sleep to prevent CPU spinning
                time.sleep(0.001)
                
        except Exception as e:
            logger.error(f"[{thread_id}] TCP tunnel error: {e}", exc_info=True)
        finally:
            if session_id:
                try:
                    close_msg = session_id.encode() + b"::CLOSE"
                    enc_close = self.crypto.encrypt(close_msg)
                    self._http_post(enc_close, f"{thread_id}-final-close")
                except:
                    pass
    
    def _handle_udp_associate(self, local_conn, client_addr, target_host, target_port, thread_id):
        """Handle UDP ASSOCIATE command with detailed logging."""
        logger.info(f"[{thread_id}] UDP ASSOCIATE to {target_host}:{target_port}")
        
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
                logger.error(f"[{thread_id}] UDP session failed: {resp_data}")
                local_conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            udp_session_id = resp_data["session"]
            logger.info(f"[{thread_id}] UDP session created: {udp_session_id}")
            
            # Create local UDP socket for relay
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(('127.0.0.1', 0))
            udp_port = udp_sock.getsockname()[1]
            udp_sock.setblocking(False)
            
            # Send SOCKS5 UDP associate response
            response = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + udp_port.to_bytes(2, 'big')
            local_conn.sendall(response)
            logger.info(f"[{thread_id}] UDP relay on 127.0.0.1:{udp_port}")
            
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
                            logger.debug(f"[{thread_id}] UDP packet #{packet_count}: {len(data)} bytes from {addr}")
                            
                            # Forward through HTTP tunnel
                            udp_message = udp_session_id.encode() + b"::UDP:" + data
                            enc_message = self.crypto.encrypt(udp_message)
                            resp_text = self._http_post(enc_message, f"{thread_id}-udp-{packet_count}")
                            plain_response = self.crypto.decrypt(resp_text)
                            
                            # Send response back to local client
                            if plain_response and plain_response != b"HEARTBEAT":
                                udp_sock.sendto(plain_response, addr)
                                logger.debug(f"[{thread_id}] UDP response: {len(plain_response)} bytes to {addr}")
                            
                            last_activity = now
                except BlockingIOError:
                    pass
                except Exception as e:
                    logger.error(f"[{thread_id}] UDP read error: {e}")
                
                # Send heartbeat if idle too long
                if now - last_activity > self.heartbeat_interval:
                    logger.debug(f"[{thread_id}] UDP heartbeat")
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
                            logger.info(f"[{thread_id}] SOCKS5 connection closed")
                            break
                except BlockingIOError:
                    pass
                except:
                    break
            
            udp_sock.close()
            logger.info(f"[{thread_id}] UDP session ended: {packet_count} packets")
            
        except Exception as e:
            logger.error(f"[{thread_id}] UDP error: {e}", exc_info=True)
    
    def start(self):
        """Start SOCKS5 proxy server."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(50)
        
        logger.info(f"SOCKS5 proxy listening on {self.socks_host}:{self.socks_port}")
        logger.info(f"Tunnel server: {self.server_url}")
        if self.proxies:
            logger.info(f"Outbound proxy: {self.config['outbound_http_proxy']}")
        logger.info(f"Max POST: {self.max_bytes} bytes, Heartbeat: {self.heartbeat_interval}s, Batch: {self.batch_wait}s")
        logger.info(f"Tip: Use --ipv4 with curl to avoid IPv6 issues")
        
        try:
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    logger.info(f"New connection from {addr}")
                    thread = threading.Thread(
                        target=self.handle_socks_connection,
                        args=(conn, addr),
                        daemon=True,
                        name=f"Tunnel-{addr[0]}:{addr[1]}"
                    )
                    thread.start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Accept error: {e}")
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.running = False
        finally:
            server_sock.close()
            logger.info("Server stopped")

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()