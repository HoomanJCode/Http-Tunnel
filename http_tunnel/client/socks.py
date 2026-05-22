"""SOCKS5 proxy server implementation.

Listens for incoming SOCKS5 connections from applications.
Parses SOCKS5 protocol and routes connections to appropriate handler.
Uses connection queue to handle burst traffic gracefully instead of rejecting.
"""

import socket
import threading
import logging
import time
import queue


class Socks5Server:
    """SOCKS5 proxy server that accepts connections and routes to tunnel."""
    
    def __init__(self, host: str, port: int, handler):
        self.host = host
        self.port = port
        self.handler = handler  # Callback: (conn, host, port, cmd, atyp)
        self.running = False
        self.logger = logging.getLogger("client.socks")
        
        # Connection management
        self.active_connections = 0
        self.max_connections = 100  # Handle browser concurrency
        self.pending_queue = queue.Queue(maxsize=200)  # Queue excess connections
        self.connection_timeout = 30  # Close idle connections after 30s
        
        self.lock = threading.Lock()
        self.connections = {}  # Track connections for cleanup
    
    def start(self):
        """Start SOCKS5 server in daemon threads."""
        self.running = True
        
        # Main accept thread
        accept_thread = threading.Thread(target=self._listen, daemon=True, name="SOCKS5-Accept")
        accept_thread.start()
        
        # Connection cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="SOCKS5-Cleanup")
        cleanup_thread.start()
    
    def stop(self):
        """Stop SOCKS5 server."""
        self.running = False
    
    def _listen(self):
        """Accept incoming SOCKS5 connections."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(1)  # Allow checking self.running
        
        try:
            server_sock.bind((self.host, self.port))
            server_sock.listen(200)  # Large backlog for burst traffic
            self.logger.info(f"SOCKS5 listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    
                    with self.lock:
                        count = self.active_connections
                    
                    if count >= self.max_connections:
                        # Queue instead of reject
                        try:
                            self.pending_queue.put((conn, addr), timeout=0.5)
                            self.logger.debug(f"Queued connection from {addr} (active: {count})")
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
        
        thread = threading.Thread(
            target=self._handle_connection,
            args=(conn, addr),
            daemon=True,
            name=f"T{addr[1]}"
        )
        thread.start()
    
    def _process_queue(self):
        """Process pending connections from queue."""
        while not self.pending_queue.empty():
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
            # SOCKS5 handshake (RFC 1928)
            conn.settimeout(10)
            
            # Greeting phase
            greeting = conn.recv(2)
            if len(greeting) < 2:
                return
            
            ver, nmethods = greeting
            if ver != 5:
                return
            
            methods = conn.recv(nmethods)
            conn.sendall(b"\x05\x00")  # No authentication
            
            # Request phase
            request = conn.recv(4)
            if len(request) < 4:
                return
            
            ver, cmd, rsv, atyp = request
            
            # Parse target address
            target_host = self._parse_address(conn, atyp)
            if target_host is None:
                conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            
            # Parse port
            port_bytes = conn.recv(2)
            target_port = int.from_bytes(port_bytes, 'big')
            
            self.logger.info(f"{target_host}:{target_port}")
            
            # Route to tunnel handler
            self.handler(conn, target_host, target_port, cmd, atyp)
            
        except socket.timeout:
            pass
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
        finally:
            # Cleanup
            with self.lock:
                self.active_connections = max(0, self.active_connections - 1)
                if conn_id in self.connections:
                    del self.connections[conn_id]
            
            try:
                conn.close()
            except:
                pass
            
            # Process queued connections
            self._process_queue()
    
    def _parse_address(self, conn: socket.socket, atyp: int) -> str:
        """Parse target address from SOCKS5 request."""
        if atyp == 1:      # IPv4
            addr_bytes = conn.recv(4)
            return socket.inet_ntoa(addr_bytes)
        elif atyp == 3:    # Domain name
            length = conn.recv(1)[0]
            return conn.recv(length).decode()
        elif atyp == 4:    # IPv6
            addr_bytes = conn.recv(16)
            return socket.inet_ntop(socket.AF_INET6, addr_bytes)
        return None
    
    def _cleanup_loop(self):
        """Periodically clean up stale connections."""
        while self.running:
            time.sleep(5)
            now = time.time()
            
            with self.lock:
                stale = [
                    cid for cid, t in self.connections.items()
                    if now - t > self.connection_timeout
                ]
                
                for cid in stale:
                    if cid in self.connections:
                        del self.connections[cid]
                        self.active_connections = max(0, self.active_connections - 1)
            
            if stale:
                self.logger.debug(f"Cleaned {len(stale)} stale connections")
            
            # Process any queued connections
            self._process_queue()