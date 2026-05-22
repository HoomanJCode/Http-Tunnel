"""UDP relay handler."""

import json
import socket
import time
import select
import logging

from http_tunnel.protocol import PROTO_UDP, create_connect_message, create_udp_message


class UdpRelay:
    """Handles UDP relay through HTTP tunnel."""
    
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.logger = logging.getLogger("client.udp")
    
    def handle(self, local_conn: socket.socket, target_host: str,
              target_port: int, thread_id: str):
        """Handle UDP ASSOCIATE request."""
        self.logger.info(f"[{thread_id}] UDP to {target_host}:{target_port}")
        
        try:
            # Create UDP session
            connect_msg = create_connect_message(target_host, target_port, PROTO_UDP)
            enc_connect = self.tunnel.crypto.encrypt(connect_msg.encode())
            resp = self.tunnel.http_post(enc_connect, f"{thread_id}-udp-connect")
            resp_data = json.loads(self.tunnel.crypto.decrypt(resp).decode())
            
            if resp_data.get("status") != "ok":
                local_conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            udp_session_id = resp_data["session"]
            
            # Create local UDP socket
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(('127.0.0.1', 0))
            udp_port = udp_sock.getsockname()[1]
            udp_sock.setblocking(False)
            
            # Send SOCKS5 response
            response = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + udp_port.to_bytes(2, 'big')
            local_conn.sendall(response)
            self.logger.info(f"[{thread_id}] UDP relay on 127.0.0.1:{udp_port}")
            
            last_activity = time.time()
            
            while self.tunnel.running and udp_session_id:
                now = time.time()
                
                # Read UDP from local
                try:
                    ready = select.select([udp_sock], [], [], 0.05)
                    if ready[0]:
                        data, addr = udp_sock.recvfrom(65536)
                        if data:
                            udp_message = create_udp_message(udp_session_id, data)
                            enc_message = self.tunnel.crypto.encrypt(udp_message)
                            resp_text = self.tunnel.http_post(enc_message, f"{thread_id}-udp")
                            plain_response = self.tunnel.crypto.decrypt(resp_text)
                            
                            if plain_response and plain_response != b"HEARTBEAT":
                                udp_sock.sendto(plain_response, addr)
                            
                            last_activity = now
                except BlockingIOError:
                    pass
                
                # Heartbeat
                if now - last_activity > self.tunnel.heartbeat_interval:
                    try:
                        heartbeat_msg = create_udp_message(udp_session_id, b"HEARTBEAT")
                        enc_heartbeat = self.tunnel.crypto.encrypt(heartbeat_msg)
                        self.tunnel.http_post(enc_heartbeat, f"{thread_id}-udp-heartbeat")
                        last_activity = now
                    except:
                        pass
                
                # Check SOCKS5 connection
                try:
                    ready = select.select([local_conn], [], [], 0.001)
                    if ready[0]:
                        data = local_conn.recv(1)
                        if not data:
                            break
                except:
                    break
            
            udp_sock.close()
            
        except Exception as e:
            self.logger.error(f"[{thread_id}] UDP error: {e}")
