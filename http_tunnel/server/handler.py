"""HTTP request handler for tunnel server - smart session management."""

import json
import socket
import time
import select
import threading
from http.server import BaseHTTPRequestHandler

from http_tunnel.crypto import TunnelCrypto
from http_tunnel.protocol import PROTO_TCP, PROTO_UDP, MSG_CLOSE, MSG_HEARTBEAT
from http_tunnel.server.session import Session, SessionManager


class TunnelRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP POST requests for tunnel data relay."""
    
    crypto: TunnelCrypto = None
    max_post_bytes: int = 5242880
    tcp_timeout: int = 60
    udp_timeout: int = 120
    connect_timeout: int = 8
    recv_buffer: int = 131072
    send_buffer: int = 131072
    read_chunk: int = 65536
    read_timeout: float = 0.01
    read_extend: float = 0.03
    logger = None
    
    sessions = SessionManager()
    
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
            self.logger.error(f"Error: {e}")
    
    def _cleanup_oldest_idle(self, max_remove=10):
        """Remove oldest idle sessions to free resources."""
        sessions = self.sessions.get_all()
        now = time.time()
        idle_sessions = []
        for sid, s in sessions.items():
            age = now - s.last_active
            if age > 5:  # Idle for more than 5 seconds
                idle_sessions.append((sid, age))
        
        # Sort by oldest first
        idle_sessions.sort(key=lambda x: x[1], reverse=True)
        
        removed = 0
        for sid, age in idle_sessions[:max_remove]:
            try:
                self.sessions.remove(sid)
                removed += 1
            except:
                pass
        
        return removed
    
    def _handle_connect(self, msg: dict):
        host = msg.get("host")
        port = msg.get("port")
        proto = msg.get("proto", PROTO_TCP)
        if not host or not port:
            self._send(json.dumps({"status": "error"}).encode())
            return
        
        # Clean up if we have too many sessions
        count = self.sessions.count()
        if count > 80:
            removed = self._cleanup_oldest_idle(max_remove=20)
            if removed and self.logger:
                self.logger.debug(f"Cleaned {removed} idle sessions (was {count})")
        
        try:
            if proto == PROTO_UDP:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
            else:
                sock = self._connect(host, port)
                sock.setblocking(False)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.recv_buffer)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.send_buffer)
            session = Session.create(sock, host, port, proto)
            self.sessions.add(session)
            self._send(json.dumps({"status": "ok", "session": session.id}).encode())
        except Exception as e:
            self._send(json.dumps({"status": "error", "reason": str(e)}).encode())
    
    def _connect(self, host: str, port: int) -> socket.socket:
        ct = self.connect_timeout
        try:
            socket.inet_pton(socket.AF_INET, host)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(ct)
            sock.connect((host, port))
            return sock
        except (socket.error, OSError):
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(min(ct, 5))
            sock.connect((host, port))
            return sock
        except (socket.error, OSError):
            pass
        try:
            addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            raise OSError(f"DNS failed: {host}")
        addrs.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
        for family, socktype, proto, canonname, sockaddr in addrs:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(ct)
                sock.connect(sockaddr)
                return sock
            except OSError:
                continue
        raise OSError(f"Could not connect to {host}:{port}")
    
    def _handle_tcp(self, client: str, session: Session, message: bytes):
        session.touch()
        
        if message == MSG_CLOSE:
            self.sessions.remove(session.id)
            self._send(b"closed")
            return
        
        if message and message != MSG_HEARTBEAT:
            try:
                session.socket.sendall(message)
                session.record_sent(len(message))
            except (BrokenPipeError, ConnectionResetError, OSError):
                self.sessions.remove(session.id)
                self._send(b"destination_closed")
                return
        
        response = b""
        try:
            ready = select.select([session.socket], [], [], self.read_timeout)
            if ready[0]:
                try:
                    chunk = session.socket.recv(self.read_chunk)
                    if not chunk:
                        self.sessions.remove(session.id)
                        self._send(b"destination_closed")
                        return
                    response = chunk
                    session.record_received(len(chunk))
                    
                    if response and len(response) < self.read_chunk:
                        ready = select.select([session.socket], [], [], self.read_extend)
                        if ready[0]:
                            try:
                                chunk = session.socket.recv(self.read_chunk)
                                if chunk:
                                    response += chunk
                                    session.record_received(len(chunk))
                            except BlockingIOError:
                                pass
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError):
                    self.sessions.remove(session.id)
                    self._send(b"destination_closed")
                    return
        except:
            self.sessions.remove(session.id)
            self._send(b"destination_closed")
            return
        
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