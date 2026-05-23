"""UDP relay handler for SOCKS5 UDP ASSOCIATE."""

import json
import socket
import time
import select
import struct
import logging

from http_tunnel.protocol import PROTO_UDP, create_connect_message


class UdpRelay:
    """Handles UDP relay through HTTP tunnel.
    
    SOCKS5 UDP ASSOCIATE flow:
    1. Client sends UDP ASSOCIATE request with DST.ADDR = 0.0.0.0, DST.PORT = 0
    2. Server creates local UDP socket and returns BND.ADDR/BND.PORT
    3. Client sends UDP packets prefixed with RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
    """
    
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.logger = logging.getLogger("client.udp")
    
    def handle(self, local_conn: socket.socket, target_host: str,
              target_port: int, thread_id: str):
        """Handle UDP ASSOCIATE request."""
        self.logger.info(f"[{thread_id}] UDP ASSOCIATE")
        
        udp_sock = None
        try:
            # Create local UDP socket for relay
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(('127.0.0.1', 0))
            udp_port = udp_sock.getsockname()[1]
            udp_sock.setblocking(False)
            
            # Send SOCKS5 UDP ASSOCIATE response
            # BND.ADDR = 127.0.0.1, BND.PORT = our UDP port
            response = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + udp_port.to_bytes(2, 'big')
            local_conn.sendall(response)
            self.logger.info(f"[{thread_id}] UDP relay on 127.0.0.1:{udp_port}")
            
            last_activity = time.time()
            packet_count = 0
            
            while self.tunnel.running:
                now = time.time()
                
                # Read UDP packets from local SOCKS5 client
                try:
                    ready = select.select([udp_sock], [], [], 0.1)
                    if ready[0]:
                        data, addr = udp_sock.recvfrom(65536)
                        if len(data) < 4:
                            continue
                        
                        # Parse SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1)
                        rsv = data[0:2]
                        frag = data[2]
                        atyp = data[3]
                        
                        # Parse target address from UDP packet
                        if atyp == 1:  # IPv4
                            udp_target = socket.inet_ntoa(data[4:8])
                            udp_port_bytes = data[8:10]
                            payload = data[10:]
                        elif atyp == 3:  # Domain
                            domain_len = data[4]
                            udp_target = data[5:5+domain_len].decode()
                            udp_port_bytes = data[5+domain_len:7+domain_len]
                            payload = data[7+domain_len:]
                        elif atyp == 4:  # IPv6
                            udp_target = socket.inet_ntop(socket.AF_INET6, data[4:20])
                            udp_port_bytes = data[20:22]
                            payload = data[22:]
                        else:
                            continue
                        
                        udp_target_port = int.from_bytes(udp_port_bytes, 'big')
                        packet_count += 1
                        
                        # Create UDP tunnel session (or reuse if exists for same target)
                        # For simplicity, create new session per packet
                        # In production, you'd cache sessions per target
                        connect_msg = create_connect_message(udp_target, udp_target_port, PROTO_UDP)
                        enc_connect = self.tunnel.crypto.encrypt(connect_msg.encode())
                        resp = self.tunnel.http_post(enc_connect, f"{thread_id}-udp-{packet_count}")
                        resp_data = json.loads(self.tunnel.crypto.decrypt(resp).decode())
                        
                        if resp_data.get("status") == "ok":
                            udp_session_id = resp_data["session"]
                            
                            # Forward the actual UDP payload
                            from http_tunnel.protocol import create_udp_message
                            udp_message = create_udp_message(udp_session_id, payload)
                            enc_message = self.tunnel.crypto.encrypt(udp_message)
                            resp_text = self.tunnel.http_post(enc_message, f"{thread_id}-udp-data-{packet_count}")
                            plain_response = self.tunnel.crypto.decrypt(resp_text)
                            
                            # Send response back to local client
                            if plain_response and plain_response != b"HEARTBEAT":
                                # Wrap in SOCKS5 UDP header for response
                                response_header = data[0:4] + data[4:10]  # Copy header from request
                                udp_sock.sendto(response_header + plain_response, addr)
                            
                            # Close UDP session
                            try:
                                close_msg = udp_session_id.encode() + b"::CLOSE"
                                enc_close = self.tunnel.crypto.encrypt(close_msg)
                                self.tunnel.http_post(enc_close, f"{thread_id}-udp-close-{packet_count}")
                            except:
                                pass
                        
                        last_activity = now
                        
                except BlockingIOError:
                    pass
                except Exception as e:
                    self.logger.error(f"[{thread_id}] UDP read error: {e}")
                
                # Check if SOCKS5 TCP connection is still alive
                try:
                    ready = select.select([local_conn], [], [], 0.001)
                    if ready[0]:
                        data = local_conn.recv(1)
                        if not data:
                            self.logger.info(f"[{thread_id}] UDP connection closed")
                            break
                except BlockingIOError:
                    pass
                except:
                    break
                
                # Timeout idle UDP relay
                if now - last_activity > 60:
                    self.logger.info(f"[{thread_id}] UDP relay timeout")
                    break
            
        except Exception as e:
            self.logger.error(f"[{thread_id}] UDP error: {e}")
        finally:
            if udp_sock:
                try:
                    udp_sock.close()
                except:
                    pass
            self.logger.info(f"[{thread_id}] UDP ended: {packet_count} packets")