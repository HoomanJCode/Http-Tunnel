"""SOCKS5 and HTTP proxy server - accepts both protocols on same port."""

import socket
import threading
import logging
import time
import struct


class Socks5Server:
    """SOCKS5 + HTTP proxy server with protocol auto-detection."""
    
    def __init__(self, host: str, port: int, handler, max_connections: int = 0):
        self.host = host
        self.port = port
        self.handler = handler  # Callback: (conn, host, port, cmd, atyp)
        self.running = False
        self.logger = logging.getLogger("client.socks")
    
    def start(self):
        self.running = True
        threading.Thread(target=self._listen, daemon=True, name="Proxy").start()
    
    def stop(self):
        self.running = False
    
    def _listen(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(1)
        try:
            server_sock.bind((self.host, self.port))
            server_sock.listen(200)
            self.logger.info(f"Proxy on {self.host}:{self.port} (SOCKS5 + HTTP)")
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True,
                        name=f"P{addr[1]}"
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
        finally:
            server_sock.close()
    
    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Detect protocol and handle accordingly."""
        try:
            conn.settimeout(5)
            first_byte = conn.recv(1)
            if not first_byte:
                return
            
            if first_byte[0] == 0x05:
                # SOCKS5
                self._handle_socks5(conn, addr, first_byte)
            elif first_byte in (b'C', b'G', b'P', b'H', b'D', b'O'):
                # HTTP proxy request
                self._handle_http_proxy(conn, addr, first_byte)
            else:
                self.logger.debug(f"Unknown protocol: 0x{first_byte[0]:02x}")
                conn.close()
        except socket.timeout:
            pass
        except Exception as e:
            self.logger.error(f"Error: {e}")
        finally:
            try:
                conn.close()
            except:
                pass
    
    def _handle_socks5(self, conn: socket.socket, addr: tuple, first_byte: bytes):
        """Handle SOCKS5 connection."""
        try:
            # Already read first byte (0x05 = version)
            ver = first_byte[0]
            nmethods = conn.recv(1)[0]
            methods = conn.recv(nmethods)
            conn.sendall(b"\x05\x00")  # No auth
            
            # Request
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
    
    def _handle_http_proxy(self, conn: socket.socket, addr: tuple, first_byte: bytes):
        """Handle HTTP proxy CONNECT or GET request.
        
        HTTP proxy format:
        CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n
        GET http://host/path HTTP/1.1\r\nHost: host\r\n\r\n
        """
        try:
            # Read the rest of the request line
            request_line = first_byte + conn.recv(4096)
            request_str = request_line.decode('utf-8', errors='ignore')
            
            # Parse first line
            lines = request_str.split('\r\n')
            if not lines:
                return
            first_line = lines[0]
            
            if first_line.startswith('CONNECT'):
                # HTTPS: CONNECT host:port HTTP/1.1
                parts = first_line.split()
                if len(parts) < 2:
                    return
                target = parts[1]  # host:port
                if ':' in target:
                    host, port_str = target.rsplit(':', 1)
                    port = int(port_str)
                else:
                    host = target
                    port = 443
                
                # Send 200 Connection Established
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                
                self.logger.info(f"HTTP CONNECT: {host}:{port}")
                self.handler(conn, host, port, 1, 3)  # cmd=1(CONNECT), atyp=3(domain)
                
            elif first_line.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ')):
                # HTTP: GET http://host/path HTTP/1.1
                parts = first_line.split()
                if len(parts) < 2:
                    return
                url = parts[1]
                # Extract host from URL
                if url.startswith('http://'):
                    url = url[7:]
                elif url.startswith('https://'):
                    url = url[8:]
                
                if '/' in url:
                    host = url.split('/')[0]
                else:
                    host = url
                
                if ':' in host:
                    host, port_str = host.rsplit(':', 1)
                    port = int(port_str)
                else:
                    port = 80
                
                self.logger.info(f"HTTP GET: {host}:{port}")
                self.handler(conn, host, port, 1, 3)  # cmd=1(CONNECT), atyp=3(domain)
            else:
                self.logger.debug(f"Unknown HTTP method: {first_line[:50]}")
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                
        except Exception as e:
            self.logger.error(f"HTTP proxy error: {e}")
            try:
                conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
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