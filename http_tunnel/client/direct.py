"""Direct connection handler for bypassed hosts."""

import socket
import time
import logging


class DirectConnector:
    """Handles direct TCP connections for bypassed hosts."""
    
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.logger = logging.getLogger("client.direct")
    
    def handle(self, local_conn: socket.socket, target_host: str,
              target_port: int, thread_id: str):
        """Handle direct TCP connection."""
        direct_sock = None
        try:
            response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            local_conn.sendall(response)
            
            self.logger.info(f"[{thread_id}] Direct to {target_host}:{target_port}")
            direct_sock = socket.create_connection((target_host, target_port), timeout=10)
            direct_sock.setblocking(False)
            local_conn.setblocking(False)
            
            while self.tunnel.running:
                # Local -> Direct
                try:
                    while True:
                        chunk = local_conn.recv(8192)
                        if not chunk:
                            return
                        direct_sock.sendall(chunk)
                except BlockingIOError:
                    pass
                except:
                    return
                
                # Direct -> Local
                try:
                    while True:
                        chunk = direct_sock.recv(8192)
                        if not chunk:
                            return
                        local_conn.sendall(chunk)
                except BlockingIOError:
                    pass
                except:
                    return
                
                time.sleep(0.001)
                
        except Exception as e:
            self.logger.error(f"[{thread_id}] Direct error: {e}")
        finally:
            if direct_sock:
                try:
                    direct_sock.close()
                except:
                    pass
