"""SOCKS5 proxy server - simple, no limits."""

import socket
import threading
import logging
import time


class Socks5Server:
    """Simple SOCKS5 proxy server with no connection limits."""
    
    def __init__(self, host: str, port: int, handler, max_connections: int = 0):
        self.host = host
        self.port = port
        self.handler = handler
        self.running = False
        self.logger = logging.getLogger("client.socks")
    
    def start(self):
        """Start SOCKS5 server."""
        self.running = True
        threading.Thread(target=self._listen, daemon=True, name="SOCKS5").start()
    
    def stop(self):
        """Stop SOCKS5 server."""
        self.running = False
    
    def _listen(self):
        """Accept incoming connections."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(1)
        
        try:
            server_sock.bind((self.host, self.port))
            server_sock.listen(200)
            self.logger.info(f"SOCKS5 on {self.host}:{self.port}")
            
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True,
                        name=f"T{addr[1]}"
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
        finally:
            server_sock.close()
    
    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Handle a single SOCKS5 connection."""
        try:
            conn.settimeout(10)
            
            greeting = conn.recv(2)
            if len(greeting) < 2:
                return
            ver, nmethods = greeting
            if ver != 5:
                return
            
            methods = conn.recv(nmethods)
            conn.sendall(b"\x05\x00")
            
            request = conn.recv(4)
            if len(request) < 4:
                return
            ver, cmd, rsv, atyp = request
            
            target_host = self._parse_address(conn, atyp)
            if target_host is None:
                conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            port_bytes = conn.recv(2)
            target_port = int.from_bytes(port_bytes, 'big')
            
            self.handler(conn, target_host, target_port, cmd, atyp)
            
        except socket.timeout:
            pass
        except Exception as e:
            self.logger.error(f"Error: {e}")
        finally:
            try:
                conn.close()
            except:
                pass
    
    def _parse_address(self, conn: socket.socket, atyp: int) -> str:
        if atyp == 1:
            return socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            length = conn.recv(1)[0]
            return conn.recv(length).decode()
        elif atyp == 4:
            return socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        return None