"""SOCKS5 + HTTP proxy server - dual protocol on single port."""

import socket
import threading
import logging
import time
import queue


class Socks5Server:
    """Proxy server that handles both SOCKS5 and HTTP CONNECT on the same port."""
    
    def __init__(self, host: str, port: int, handler, max_connections: int = 0):
        self.host = host
        self.port = port
        self.handler = handler
        self.max_connections = max_connections
        self.running = False
        self.logger = logging.getLogger("client.socks")
        self.active_connections = 0
        self.pending_queue = queue.Queue(maxsize=200)
        self.connection_timeout = 30
        self.lock = threading.Lock()
        self.connections = {}
    
    def start(self):
        self.running = True
        threading.Thread(target=self._listen, daemon=True, name="Proxy-Accept").start()
        threading.Thread(target=self._cleanup_loop, daemon=True, name="Proxy-Cleanup").start()
    
    def stop(self):
        self.running = False
    
    def _listen(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(1)
        
        try:
            server_sock.bind((self.host, self.port))
            server_sock.listen(200)
            self.logger.info(f"Proxy on {self.host}:{self.port} (SOCKS5 + HTTP CONNECT)")
            
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    
                    with self.lock:
                        count = self.active_connections
                    
                    if self.max_connections > 0 and count >= self.max_connections:
                        try:
                            self.pending_queue.put((conn, addr), timeout=0.5)
                        except queue.Full:
                            conn.close()
                    else:
                        self._start_connection(conn, addr)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
        finally:
            server_sock.close()
    
    def _start_connection(self, conn: socket.socket, addr: tuple):
        with self.lock:
            self.active_connections += 1
            self.connections[id(conn)] = time.time()
        
        threading.Thread(
            target=self._handle_connection,
            args=(conn, addr),
            daemon=True,
            name=f"P{addr[1]}"
        ).start()
    
    def _process_queue(self):
        while not self.pending_queue.empty():
            if self.max_connections > 0:
                with self.lock:
                    if self.active_connections >= self.max_connections:
                        break
            try:
                conn, addr = self.pending_queue.get_nowait()
                self._start_connection(conn, addr)
            except queue.Empty:
                break
            except Exception:
                pass
    
    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Handle connection - detect SOCKS5 vs HTTP CONNECT by first bytes."""
        conn_id = id(conn)
        
        try:
            conn.settimeout(10)
            
            # Peek at first byte to detect protocol
            first_byte = conn.recv(1, socket.MSG_PEEK)
            if not first_byte:
                return
            
            if first_byte[0] == 0x05:
                # SOCKS5
                self._handle_socks5(conn, addr)
            else:
                # Try HTTP CONNECT
                self._handle_http_connect(conn, addr)
            
        except socket.timeout:
            pass
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
        finally:
            with self.lock:
                self.active_connections = max(0, self.active_connections - 1)
                if conn_id in self.connections:
                    del self.connections[conn_id]
            try:
                conn.close()
            except:
                pass
            self._process_queue()
    
    def _handle_socks5(self, conn: socket.socket, addr: tuple):
        """Handle SOCKS5 connection."""
        try:
            # Greeting
            greeting = conn.recv(2)
            if len(greeting) < 2:
                return
            ver, nmethods = greeting
            if ver != 5:
                return
            
            methods = conn.recv(nmethods)
            conn.sendall(b"\x05\x00")
            
            # Request
            request = conn.recv(4)
            if len(request) < 4:
                return
            ver, cmd, rsv, atyp = request
            
            target_host = self._parse_socks5_address(conn, atyp)
            if target_host is None:
                conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            port_bytes = conn.recv(2)
            target_port = int.from_bytes(port_bytes, 'big')
            
            self.logger.info(f"SOCKS5 {target_host}:{target_port}")
            self.handler(conn, target_host, target_port, cmd, atyp)
            
        except socket.timeout:
            pass
        except Exception as e:
            self.logger.error(f"SOCKS5 error: {e}")
    
    def _handle_http_connect(self, conn: socket.socket, addr: tuple):
        """Handle HTTP CONNECT proxy request."""
        try:
            # Read the CONNECT request line
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            
            request_line = data.split(b"\r\n")[0].decode()
            
            # Parse: CONNECT host:port HTTP/1.1
            if not request_line.startswith("CONNECT "):
                # Maybe a plain HTTP request - respond with 405
                conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return
            
            parts = request_line.split()
            if len(parts) < 2:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            
            target = parts[1]  # host:port
            if ":" in target:
                target_host = target.rsplit(":", 1)[0]
                target_port = int(target.rsplit(":", 1)[1])
            else:
                target_host = target
                target_port = 443  # Default HTTPS
            
            self.logger.info(f"HTTP-CONNECT {target_host}:{target_port}")
            
            # Send 200 Connection Established
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            
            # Route as TCP CONNECT (cmd=1, atyp=3 for hostname)
            self.handler(conn, target_host, target_port, 1, 3)
            
        except Exception as e:
            self.logger.error(f"HTTP CONNECT error: {e}")
    
    def _parse_socks5_address(self, conn: socket.socket, atyp: int) -> str:
        if atyp == 1:
            return socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            length = conn.recv(1)[0]
            return conn.recv(length).decode()
        elif atyp == 4:
            return socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        return None
    
    def _cleanup_loop(self):
        while self.running:
            time.sleep(5)
            now = time.time()
            with self.lock:
                stale = [cid for cid, t in self.connections.items() if now - t > self.connection_timeout]
                for cid in stale:
                    if cid in self.connections:
                        del self.connections[cid]
                        self.active_connections = max(0, self.active_connections - 1)
            if stale:
                self.logger.debug(f"Cleaned {len(stale)} stale connections")
            self._process_queue()