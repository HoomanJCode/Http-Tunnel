"""HTTP request handler for tunnel server - simple and clean."""

import json
import socket
import time
import select
import struct
from http.server import BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor

from http_tunnel.crypto import TunnelCrypto
from http_tunnel.compression import compress_data, decompress_data, COMPRESS_ZLIB
from http_tunnel.protocol import PROTO_TCP, PROTO_UDP, MSG_CLOSE, MSG_HEARTBEAT
from http_tunnel.server.session import Session, SessionManager


class TunnelRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP POST requests for tunnel data relay."""
    
    crypto: TunnelCrypto = None
    max_post_bytes: int = 5242880
    tcp_timeout: int = 60
    udp_timeout: int = 120
    compression: bool = True
    logger = None
    
    sessions = SessionManager()
    executor = ThreadPoolExecutor(max_workers=50)
    
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error: {e}")
    
    def do_POST(self):
        client = self.client_address[0]
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > self.max_post_bytes:
                self.send_error(413)
                return
            try:
                body = self.rfile.read(content_length).decode()
            except (ConnectionResetError, BrokenPipeError, OSError):
                return
            try:
                plain = self.crypto.decrypt(body)
            except Exception:
                self.send_error(400)
                return
            try:
                msg = json.loads(plain.decode())
                if msg.get("type") == "ping":
                    self._send(b"pong")
                    return
                elif msg.get("type") == "connect":
                    self.logger.info(f"[{client}] CONNECT {msg.get('host')}:{msg.get('port')}")
                    self._handle_connect(msg)
                    return
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            if b'::' in plain:
                parts = plain.split(b'::', 1)
                session_id = parts[0].decode('ascii', errors='ignore')
                message = parts[1] if len(parts) > 1 else b""
                session = self.sessions.get(session_id)
                if session:
                    if message.startswith(b"UDP:"):
                        self._handle_udp(client, session, message[4:])
                    else:
                        self._handle_tcp(client, session, message)
                else:
                    self._send(b"invalid_session")
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            self.logger.error(f"[{client}] Error: {e}")
    
    def _handle_connect(self, msg: dict):
        host = msg.get("host")
        port = msg.get("port")
        proto = msg.get("proto", PROTO_TCP)
        if not host or not port:
            self._send(json.dumps({"status": "error"}).encode())
            return
        try:
            if proto == PROTO_UDP:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
            else:
                sock = self._connect(host, port)
                sock.setblocking(False)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            session = Session.create(sock, host, port, proto)
            self.sessions.add(session)
            self._send(json.dumps({"status": "ok", "session": session.id}).encode())
        except Exception as e:
            self.logger.error(f"Connect failed {host}:{port}: {e}")
            self._send(json.dumps({"status": "error", "reason": str(e)}).encode())
    
    def _connect(self, host: str, port: int) -> socket.socket:
        """Connect to host:port. Tries IPv4 first, then hostname resolution."""
        try:
            socket.inet_pton(socket.AF_INET, host)
            return socket.create_connection((host, port), timeout=10)
        except socket.error:
            pass
        
        try:
            socket.inet_pton(socket.AF_INET6, host)
            try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                return sock
            except OSError as e:
                raise OSError(f"IPv6 not available: {e}")
        except socket.error:
            pass
        
        try:
            addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            raise OSError(f"DNS resolution failed for {host}")
        
        addrs.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
        
        last_error = None
        for family, socktype, proto, canonname, sockaddr in addrs:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(10)
                sock.connect(sockaddr)
                return sock
            except OSError as e:
                last_error = e
                continue
        
        raise OSError(f"Could not connect to {host}:{port}: {last_error}")
    
    def _read_tls_record(self, sock) -> bytes:
        """Read a complete TLS record from socket.
        
        TLS records have a 5-byte header:
        - Byte 0: Content type (0x16=Handshake, 0x17=App data)
        - Bytes 1-2: TLS version
        - Bytes 3-4: Record length (big-endian)
        
        Returns the complete TLS record or empty bytes on error/timeout.
        """
        try:
            # Try to read the 5-byte TLS header
            ready = select.select([sock], [], [], 0.05)
            if not ready[0]:
                return None  # No data yet
            
            # Peek at first byte to check if it's TLS
            first_byte = sock.recv(1, socket.MSG_PEEK)
            if not first_byte:
                return b""
            
            # If it's not TLS, just read whatever is available
            if first_byte[0] not in [0x16, 0x17, 0x14, 0x15, 0x18]:
                data = b""
                while True:
                    ready = select.select([sock], [], [], 0.01)
                    if ready[0]:
                        try:
                            chunk = sock.recv(65536)
                            if not chunk:
                                break
                            data += chunk
                        except BlockingIOError:
                            break
                    else:
                        break
                return data if data else None
            
            # Read the full 5-byte header
            header = b""
            while len(header) < 5:
                ready = select.select([sock], [], [], 0.5)
                if not ready[0]:
                    return None
                try:
                    chunk = sock.recv(5 - len(header))
                    if not chunk:
                        return b""
                    header += chunk
                except BlockingIOError:
                    continue
            
            # Parse record length from bytes 3-4
            record_length = struct.unpack('!H', header[3:5])[0]
            total_length = 5 + record_length
            
            # Read the rest of the record
            data = header
            while len(data) < total_length:
                remaining = total_length - len(data)
                ready = select.select([sock], [], [], 0.5)
                if not ready[0]:
                    # Timeout - return what we have so far
                    break
                try:
                    chunk = sock.recv(min(remaining, 65536))
                    if not chunk:
                        break
                    data += chunk
                except BlockingIOError:
                    continue
            
            return data
            
        except Exception:
            return None
    
    def _handle_tcp(self, client: str, session: Session, message: bytes):
        """Handle TCP data relay with TLS record reassembly."""
        session.touch()
        
        if message == MSG_CLOSE:
            self.logger.info(f"[{client}] Session {session.id} closed")
            self.sessions.remove(session.id)
            self._send(b"closed")
            return
        
        # Decompress incoming data from client
        if message and message != MSG_HEARTBEAT:
            try:
                message = decompress_data(message)
            except:
                pass
        
        # Forward to destination
        if message and message != MSG_HEARTBEAT:
            try:
                session.socket.sendall(message)
                session.record_sent(len(message))
            except (BrokenPipeError, ConnectionResetError, OSError):
                self.sessions.remove(session.id)
                self._send(b"destination_closed")
                return
        
        # Read response - try to get complete TLS record
        response = b""
        try:
            # Try TLS-aware read first
            tls_data = self._read_tls_record(session.socket)
            if tls_data is not None:
                if tls_data == b"":
                    self.sessions.remove(session.id)
                    response = b"destination_closed"
                else:
                    response = tls_data
                    session.record_received(len(tls_data))
            elif response == b"":
                # No data available, send empty response (heartbeat will follow)
                pass
        except:
            self.sessions.remove(session.id)
            response = b"destination_closed"
        
        self._send(response if response else b"")
    
    def _handle_udp(self, client: str, session: Session, data: bytes):
        session.touch()
        if data and data not in [MSG_CLOSE, MSG_HEARTBEAT]:
            try:
                session.socket.sendto(data, (session.host, session.port))
                session.record_sent(len(data))
            except:
                pass
        response = b""
        try:
            ready = select.select([session.socket], [], [], 0.001)
            if ready[0]:
                data, addr = session.socket.recvfrom(65536)
                response = data
        except:
            pass
        self._send(response if response else b"")
    
    def _send(self, data: bytes):
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
    
    def log_message(self, format, *args):
        pass