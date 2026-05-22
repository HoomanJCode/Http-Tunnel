"""HTTP request handler for tunnel server."""

import json
import socket
import time
import select
from http.server import BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor

from http_tunnel.crypto import TunnelCrypto
from http_tunnel.compression import compress_data, decompress_data, COMPRESS_ZLIB
from http_tunnel.protocol import PROTO_TCP, PROTO_UDP, parse_session_message
from http_tunnel.server.session import Session, SessionManager


class TunnelRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP POST requests for tunnel data."""
    
    # Class-level configuration
    crypto: TunnelCrypto = None
    max_post_bytes: int = 5242880
    tcp_timeout: int = 60
    udp_timeout: int = 120
    compression: bool = True
    logger = None
    
    # Shared resources
    sessions = SessionManager()
    executor = ThreadPoolExecutor(max_workers=50)
    
    def handle_one_request(self):
        """Handle a single HTTP request with error catching."""
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error handling request: {e}")
    
    def do_POST(self):
        """Process POST request containing tunnel data."""
        client = self.client_address[0]
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            
            if content_length > self.max_post_bytes:
                self.logger.warning(f"[{client}] Payload too large: {content_length}")
                self.send_error(413, "Payload too large")
                return
            
            try:
                body = self.rfile.read(content_length).decode()
            except (ConnectionResetError, BrokenPipeError, OSError):
                return
            except Exception as e:
                self.logger.error(f"[{client}] Error reading body: {e}")
                self.send_error(400, "Bad request")
                return
            
            try:
                plain = self.crypto.decrypt(body)
            except Exception:
                self.logger.warning(f"[{client}] Decryption failed")
                self.send_error(400, "Decryption failed")
                return
            
            # Handle control messages
            try:
                msg = json.loads(plain.decode())
                if msg.get("type") == "ping":
                    self._send_encrypted(b"pong")
                    return
                elif msg.get("type") == "connect":
                    self.logger.info(f"[{client}] CONNECT to {msg.get('host')}:{msg.get('port')}")
                    self._handle_connect(msg)
                    return
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            
            # Handle session data messages
            session_id, message = parse_session_message(plain)
            if session_id:
                session = self.sessions.get(session_id)
                if session:
                    if message.startswith(b"UDP:"):
                        self._handle_udp_data(client, session, message[4:])
                    else:
                        self._handle_tcp_data(client, session, message)
                else:
                    self.logger.warning(f"[{client}] Unknown session: {session_id}")
                    self._send_encrypted(b"invalid_session")
            else:
                self._send_encrypted(b"invalid_format")
                
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            self.logger.error(f"[{client}] Error: {e}")
            try:
                self.send_error(500)
            except:
                pass
    
    def _handle_connect(self, msg: dict) -> None:
        """Handle connection request."""
        host = msg.get("host")
        port = msg.get("port")
        proto = msg.get("proto", PROTO_TCP)
        
        if not host or not port:
            self._send_encrypted(json.dumps({
                "status": "error", "reason": "Missing host/port"
            }).encode())
            return
        
        try:
            if proto == PROTO_UDP:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                self.logger.info(f"UDP session for {host}:{port}")
            else:
                sock = self._resolve_and_connect(host, port)
                sock.setblocking(False)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.logger.info(f"TCP session for {host}:{port}")
            
            session = Session.create(sock, host, port, proto)
            self.sessions.add(session)
            
            self._send_encrypted(json.dumps({
                "status": "ok", "session": session.id, "proto": proto
            }).encode())
            
        except Exception as e:
            self.logger.error(f"Connection failed to {host}:{port}: {e}")
            self._send_encrypted(json.dumps({
                "status": "error", "reason": str(e)
            }).encode())
    
    def _resolve_and_connect(self, host: str, port: int) -> socket.socket:
        """Resolve hostname and establish TCP connection."""
        # Try as raw IPv4
        try:
            socket.inet_pton(socket.AF_INET, host)
            self.logger.info(f"Connecting to {host}:{port}")
            return socket.create_connection((host, port), timeout=10)
        except socket.error:
            pass
        
        # Try as raw IPv6
        try:
            socket.inet_pton(socket.AF_INET6, host)
            try:
                return socket.create_connection((host, port), timeout=10)
            except OSError as e:
                self.logger.error(f"IPv6 failed: {e}")
                raise
        except socket.error:
            pass
        
        # Resolve hostname
        self.logger.info(f"Resolving {host}:{port}...")
        addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        addrs.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
        
        for family, socktype, proto, canonname, sockaddr in addrs:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(10)
                sock.connect(sockaddr)
                self.logger.info(f"Connected to {sockaddr[0]}:{sockaddr[1]}")
                return sock
            except OSError:
                continue
        
        raise OSError(f"Could not connect to {host}:{port}")
    
    def _handle_tcp_data(self, client: str, session: Session, message: bytes) -> None:
        """Handle TCP data relay."""
        session.touch()
        
        if message == b"CLOSE":
            self.logger.info(f"[{client}] Session {session.id} closed")
            self.logger.debug(f"[{client}] Stats: {session.requests} req, "
                            f"{session.bytes_sent}B sent, {session.bytes_received}B recv")
            self.sessions.remove(session.id)
            self._send_encrypted(b"closed")
            return
        
        # Decompress incoming data
        if message and message not in [b"HEARTBEAT", b"CLOSE"]:
            if self.compression:
                try:
                    message = decompress_data(message)
                except Exception:
                    pass
        
        # Forward to destination
        if message and message != b"HEARTBEAT":
            try:
                total_sent = 0
                while total_sent < len(message):
                    try:
                        sent = session.socket.send(message[total_sent:])
                        if sent > 0:
                            total_sent += sent
                            session.record_sent(sent)
                        else:
                            break
                    except BlockingIOError:
                        ready = select.select([], [session.socket], [], 0.1)
                        if not ready[1]:
                            break
            except (BrokenPipeError, ConnectionResetError, OSError):
                self.sessions.remove(session.id)
                self._send_encrypted(b"destination_closed")
                return
        
        # Read response from destination
        response_data = self._read_from_socket(session)
        
        # Compress response
        if response_data and response_data not in [b"destination_closed", b"closed"]:
            if self.compression:
                try:
                    response_data = compress_data(response_data, COMPRESS_ZLIB, 100)
                except Exception:
                    pass
        
        self._send_encrypted(response_data if response_data else b"")
    
    def _handle_udp_data(self, client: str, session: Session, data: bytes) -> None:
        """Handle UDP data relay."""
        session.touch()
        
        if data and data not in [b"CLOSE", b"HEARTBEAT"]:
            try:
                addr = (session.host, session.port)
                session.socket.sendto(data, addr)
                session.record_sent(len(data))
            except Exception:
                pass
        
        response_data = b""
        try:
            ready = select.select([session.socket], [], [], 0.001)
            if ready[0]:
                data, addr = session.socket.recvfrom(65536)
                response_data = data
                session.record_received(len(data))
        except (BlockingIOError, socket.error):
            pass
        
        if response_data and self.compression:
            try:
                response_data = compress_data(response_data, COMPRESS_ZLIB, 100)
            except Exception:
                pass
        
        self._send_encrypted(response_data if response_data else b"")
    
    def _read_from_socket(self, session: Session) -> bytes:
        """Read available data from session socket."""
        response_data = b""
        try:
            while True:
                ready = select.select([session.socket], [], [], 0.01)
                if ready[0]:
                    try:
                        chunk = session.socket.recv(65536)
                        if not chunk:
                            self.logger.info(f"Session {session.id}: Destination closed")
                            self.sessions.remove(session.id)
                            return b"destination_closed"
                        response_data += chunk
                        session.record_received(len(chunk))
                        if len(response_data) >= self.max_post_bytes - 2000:
                            break
                    except BlockingIOError:
                        break
                    except (ConnectionResetError, BrokenPipeError):
                        self.sessions.remove(session.id)
                        return b"destination_closed"
                else:
                    break
        except Exception:
            self.sessions.remove(session.id)
            return b"destination_closed"
        
        return response_data
    
    def _send_encrypted(self, data: bytes) -> None:
        """Encrypt and send response."""
        try:
            token = self.crypto.encrypt(data)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(token)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(token.encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            if self.logger:
                self.logger.error(f"Send error: {e}")
    
    def log_message(self, format, *args):
        """Override to use custom logger."""
        if args and "200" not in str(args[0]):
            if self.logger:
                self.logger.debug(f"[{self.client_address[0]}] {format % args}")
