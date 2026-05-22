"""SOCKS5 proxy server implementation.

Listens for incoming SOCKS5 connections from applications.
Parses SOCKS5 protocol and routes connections to appropriate handler.
Includes connection limiting to prevent overwhelming the tunnel.
"""

import socket
import threading
import logging
import time


class Socks5Server:
    """SOCKS5 proxy server that accepts connections and routes to tunnel."""
    
    def __init__(self, host: str, port: int, handler):
        self.host = host
        self.port = port
        self.handler = handler  # Callback: (conn, host, port, cmd, atyp)
        self.running = False
        self.logger = logging.getLogger("client.socks")
        self.active_connections = 0
        self.max_connections = 30  # Limit concurrent connections
        self.lock = threading.Lock()
    
    def start(self):
        """Start SOCKS5 server in a daemon thread."""
        self.running = True
        thread = threading.Thread(target=self._listen, daemon=True, name="SOCKS5")
        thread.start()
    
    def stop(self):
        """Stop SOCKS5 server."""
        self.running = False
    
    def _listen(self):
        """Listen for and accept SOCKS5 connections."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_sock.bind((self.host, self.port))
            server_sock.listen(50)
            self.logger.info(f"SOCKS5 listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    
                    # Check connection limit
                    with self.lock:
                        if self.active_connections >= self.max_connections:
                            self.logger.warning(f"Too many connections ({self.active_connections}), rejecting {addr}")
                            conn.close()
                            continue
                        self.active_connections += 1
                    
                    thread = threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True,
                        name=f"T{addr[1]}"
                    )
                    thread.start()
                    
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
        except Exception as e:
            self.logger.error(f"SOCKS5 server error: {e}")
        finally:
            server_sock.close()
    
    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Handle a single SOCKS5 connection."""
        try:
            # SOCKS5 handshake (RFC 1928)
            conn.settimeout(10)
            
            # Greeting phase
            greeting = conn.recv(2)
            if len(greeting) < 2:
                return
            
            ver, nmethods = greeting
            if ver != 5:  # Only SOCKS5 supported
                return
            
            methods = conn.recv(nmethods)
            conn.sendall(b"\x05\x00")  # No authentication required
            
            # Request phase
            request = conn.recv(4)
            if len(request) < 4:
                return
            
            ver, cmd, rsv, atyp = request
            
            # Parse target address based on address type
            target_host = self._parse_address(conn, atyp)
            if target_host is None:
                conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            # Parse port (2 bytes, big-endian)
            port_bytes = conn.recv(2)
            target_port = int.from_bytes(port_bytes, 'big')
            
            self.logger.info(f"{target_host}:{target_port}")
            
            # Route to handler callback
            self.handler(conn, target_host, target_port, cmd, atyp)
            
        except socket.timeout:
            pass
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
        finally:
            with self.lock:
                self.active_connections = max(0, self.active_connections - 1)
            try:
                conn.close()
            except:
                pass
    
    def _parse_address(self, conn: socket.socket, atyp: int) -> str:
        """Parse target address from SOCKS5 request."""
        if atyp == 1:      # IPv4 (4 bytes)
            addr_bytes = conn.recv(4)
            return socket.inet_ntoa(addr_bytes)
        elif atyp == 3:    # Domain name (length byte + name)
            length = conn.recv(1)[0]
            return conn.recv(length).decode()
        elif atyp == 4:    # IPv6 (16 bytes)
            addr_bytes = conn.recv(16)
            return socket.inet_ntop(socket.AF_INET6, addr_bytes)
        return None