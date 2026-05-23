"""SOCKS5 proxy server implementation."""

import socket
import threading
import logging
import time
import queue


class Socks5Server:
    """SOCKS5 proxy server with configurable connection limits."""
    
    def __init__(self, host: str, port: int, handler, max_connections: int = 0):
        self.host = host
        self.port = port
        self.handler = handler
        self.max_connections = max_connections  # 0 = unlimited
        self.running = False
        self.logger = logging.getLogger("client.socks")
        self.active_connections = 0
        self.pending_queue = queue.Queue(maxsize=200)
        self.connection_timeout = 30
        self.lock = threading.Lock()
        self.connections = {}
    
    def start(self):
        """Start SOCKS5 server."""
        self.running = True
        threading.Thread(target=self._listen, daemon=True, name="SOCKS5-Accept").start()
        threading.Thread(target=self._cleanup_loop, daemon=True, name="SOCKS5-Cleanup").start()
    
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
            self.logger.info(f"SOCKS5 on {self.host}:{self.port}" + 
                           (f" (max {self.max_connections})" if self.max_connections > 0 else " (unlimited)"))
            
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    
                    with self.lock:
                        count = self.active_connections
                    
                    # Check limit only if max_connections > 0
                    if self.max_connections > 0 and count >= self.max_connections:
                        try:
                            self.pending_queue.put((conn, addr), timeout=0.5)
                        except queue.Full:
                            self.logger.warning(f"Queue full, rejecting {addr}")
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
        """Start handling a new connection."""
        with self.lock:
            self.active_connections += 1
            self.connections[id(conn)] = time.time()
        
        threading.Thread(
            target=self._handle_connection,
            args=(conn, addr),
            daemon=True,
            name=f"T{addr[1]}"
        ).start()
    
    def _process_queue(self):
        """Process pending connections."""
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
        """Handle a single SOCKS5 connection."""
        conn_id = id(conn)
        
        try:
            conn.settimeout(10)
            
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
    
    def _parse_address(self, conn: socket.socket, atyp: int) -> str:
        """Parse target address from SOCKS5 request."""
        if atyp == 1:
            return socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            length = conn.recv(1)[0]
            return conn.recv(length).decode()
        elif atyp == 4:
            return socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        return None
    
    def _cleanup_loop(self):
        """Clean up stale connections."""
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