import json
import socket
import threading
import time
import select
import os
import sys
import struct
from concurrent.futures import ThreadPoolExecutor
import requests
from common import TunnelCrypto, generate_config_wizard, UDPPacket

class SocksToHttpTunnel:
    def __init__(self, config_path="client_config.json"):
        if not os.path.exists(config_path):
            print(f"Config not found. Running wizard...")
            if not generate_config_wizard(config_path, "client"):
                raise RuntimeError("Setup cancelled.")
        
        with open(config_path) as f:
            self.config = json.load(f)
        
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
        self.http_timeout = self.config.get("http_timeout", 30)
        self.reconnect_delay = self.config.get("reconnect_delay", 0.5)
        self.udp_timeout = self.config.get("udp_timeout", 30)
        
        socks_addr = self.config["socks_listen"].split(":")
        self.socks_host = socks_addr[0]
        self.socks_port = int(socks_addr[1])
        
        self.running = True
        self.udp_sessions = {}
        self.udp_lock = threading.Lock()
        
        # Connection pool
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "text/plain",
            "Connection": "keep-alive"
        })
        # Connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=1
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def _http_post(self, body: str) -> str:
        """Send POST with retry logic."""
        last_error = None
        for attempt in range(2):  # Reduced retries for speed
            try:
                resp = self.session.post(
                    self.server_url,
                    data=body,
                    proxies=self.proxies if self.proxies else None,
                    timeout=self.http_timeout
                )
                resp.raise_for_status()
                return resp.text
            except Exception as e:
                last_error = e
                if attempt == 1:
                    raise
                time.sleep(0.1)
        raise last_error
    
    def _create_tunnel(self, target_host, target_port, is_udp=False):
        """Create a tunnel session on server."""
        if is_udp:
            msg = json.dumps({"type": "udp_associate"})
        else:
            msg = json.dumps({"type": "connect", "host": target_host, "port": target_port})
        
        enc_msg = self.crypto.encrypt(msg.encode())
        resp = self._http_post(enc_msg)
        resp_data = json.loads(self.crypto.decrypt(resp).decode())
        
        if resp_data.get("status") != "ok":
            raise Exception(f"Server refused: {resp_data}")
        
        return resp_data["session"]
    
    def _send_session_message(self, session_id, message):
        """Send message for existing session."""
        session_msg = session_id.encode() + b"::" + message
        enc_msg = self.crypto.encrypt(session_msg)
        resp_text = self._http_post(enc_msg)
        return self.crypto.decrypt(resp_text)
    
    def handle_socks_connection(self, local_conn: socket.socket):
        """Handle SOCKS5 TCP connection."""
        session_id = None
        target_host = None
        target_port = None
        
        try:
            # SOCKS5 handshake
            local_conn.settimeout(30)
            
            # Greeting
            data = local_conn.recv(262)
            if len(data) < 2 or data[0] != 5:
                local_conn.close()
                return
            nmethods = data[1]
            local_conn.recv(nmethods)
            local_conn.sendall(b"\x05\x00")
            
            # Request
            data = local_conn.recv(262)
            if len(data) < 4:
                local_conn.close()
                return
            
            ver, cmd, rsv, atyp = data[0], data[1], data[2], data[3]
            
            # Handle UDP ASSOCIATE
            if cmd == 3:  # UDP ASSOCIATE
                self._handle_udp_associate(local_conn)
                return
            
            if cmd != 1:  # CONNECT
                local_conn.sendall(b"\x05\x07\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
                local_conn.close()
                return
            
            # Parse address
            pos = 4
            if atyp == 1:  # IPv4
                target_host = socket.inet_ntoa(data[pos:pos+4])
                pos += 4
            elif atyp == 3:  # Domain
                length = data[pos]
                pos += 1
                target_host = data[pos:pos+length].decode()
                pos += length
            else:
                local_conn.close()
                return
            
            target_port = struct.unpack('!H', data[pos:pos+2])[0]
            
            # Send success immediately
            local_conn.sendall(
                b"\x05\x00\x00\x01" + 
                socket.inet_aton("0.0.0.0") + 
                struct.pack('!H', target_port)
            )
            
            # Create tunnel
            session_id = self._create_tunnel(target_host, target_port)
            
            # Data relay loop
            local_conn.setblocking(False)
            buffer_out = b""
            last_send = time.time()
            last_response = time.time()
            
            while self.running and session_id:
                now = time.time()
                
                # Check for timeout
                if now - last_response > 60:
                    print(f"Session timeout: {target_host}:{target_port}")
                    break
                
                # Read from local
                try:
                    while True:
                        chunk = local_conn.recv(65536)
                        if not chunk:
                            self._send_session_message(session_id, b"CLOSE")
                            local_conn.close()
                            return
                        buffer_out += chunk
                        if len(buffer_out) >= self.max_bytes - 2000:
                            break
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError):
                    break
                
                # Decide to send
                force_send = (
                    len(buffer_out) >= self.max_bytes - 2000 or
                    (len(buffer_out) > 0 and now - last_send >= self.batch_wait)
                )
                heartbeat = (len(buffer_out) == 0 and now - last_send >= self.heartbeat_interval)
                
                if force_send or heartbeat:
                    if buffer_out:
                        payload = buffer_out[:self.max_bytes - 2000]
                        buffer_out = buffer_out[self.max_bytes - 2000:]
                    else:
                        payload = b"HEARTBEAT"
                    
                    try:
                        response = self._send_session_message(session_id, payload)
                        last_response = time.time()
                        
                        if response == b"destination_closed":
                            try:
                                local_conn.sendall(response)
                            except:
                                pass
                            break
                        elif response:
                            try:
                                local_conn.sendall(response)
                            except:
                                break
                        
                        last_send = now
                        
                    except Exception as e:
                        time.sleep(0.1)
                        continue
                
                time.sleep(0.001)
                
        except Exception as e:
            pass
        finally:
            if session_id:
                try:
                    self._send_session_message(session_id, b"CLOSE")
                except:
                    pass
            try:
                local_conn.close()
            except:
                pass
    
    def _handle_udp_associate(self, local_conn):
        """Handle SOCKS5 UDP ASSOCIATE."""
        # Get client address for response
        local_addr = local_conn.getsockname()
        
        # Create UDP socket for client
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind((self.socks_host, 0))
        udp_port = udp_sock.getsockname()[1]
        
        # Send SOCKS5 response with UDP port
        response = (
            b"\x05\x00\x00\x01" +
            socket.inet_aton(self.socks_host) +
            struct.pack('!H', udp_port)
        )
        local_conn.sendall(response)
        
        # Create UDP tunnel on server
        try:
            session_id = self._create_tunnel(None, None, is_udp=True)
        except:
            local_conn.close()
            udp_sock.close()
            return
        
        # Store UDP session
        with self.udp_lock:
            self.udp_sessions[local_conn.fileno()] = {
                'session_id': session_id,
                'socket': udp_sock,
                'local_conn': local_conn,
                'last_active': time.time()
            }
        
        # Start UDP relay thread
        threading.Thread(
            target=self._udp_relay,
            args=(local_conn, udp_sock, session_id),
            daemon=True
        ).start()
    
    def _udp_relay(self, local_conn, udp_sock, session_id):
        """Relay UDP packets through HTTP tunnel."""
        buffer = b""
        last_send = time.time()
        
        while self.running and session_id:
            now = time.time()
            
            # Read from local UDP socket
            try:
                ready = select.select([udp_sock], [], [], 0.05)
                if ready[0]:
                    data, addr = udp_sock.recvfrom(65536)
                    # Encode with SOCKS5 UDP header
                    packet = UDPPacket.encode(data, addr)
                    buffer += packet
            except BlockingIOError:
                pass
            except OSError:
                break
            
            # Send if we have data or it's time for heartbeat
            if buffer or now - last_send >= self.heartbeat_interval:
                payload = buffer[:self.max_bytes - 2000] if buffer else b"HEARTBEAT"
                buffer = buffer[self.max_bytes - 2000:] if buffer else b""
                
                try:
                    response = self._send_session_message(session_id, payload)
                    last_send = now
                    
                    if response and response != b"HEARTBEAT":
                        # Parse response as UDP packet
                        resp_data, resp_addr = UDPPacket.decode(response)
                        if resp_data and resp_addr:
                            # Forward to SOCKS5 client
                            udp_sock.sendto(resp_data, resp_addr)
                except:
                    time.sleep(0.1)
                    continue
            
            # Check if TCP control connection is still alive
            try:
                local_conn.getpeername()
            except:
                break
            
            time.sleep(0.001)
        
        # Cleanup
        try:
            self._send_session_message(session_id, b"CLOSE")
        except:
            pass
        try:
            local_conn.close()
        except:
            pass
        try:
            udp_sock.close()
        except:
            pass
        
        with self.udp_lock:
            self.udp_sessions.pop(local_conn.fileno(), None)
    
    def start(self):
        """Start SOCKS5 listener."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.socks_host, self.socks_port))
        server_sock.listen(50)
        print(f"SOCKS5 tunnel on {self.socks_host}:{self.socks_port}")
        print(f"Server: {self.server_url}")
        if self.proxies:
            print(f"Proxy: {self.config['outbound_http_proxy']}")
        
        # Thread pool for handling connections
        executor = ThreadPoolExecutor(max_workers=50)
        
        try:
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    executor.submit(self.handle_socks_connection, conn)
                except Exception as e:
                    if self.running:
                        pass
        except KeyboardInterrupt:
            print("\nShutting down...")
            self.running = False
        finally:
            server_sock.close()
            executor.shutdown(wait=False)

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()