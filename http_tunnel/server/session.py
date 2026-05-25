"""Session management for tunnel connections."""

import time
import uuid
import threading

from http_tunnel.protocol import PROTO_UDP


class Session:
    """Represents a single tunnel session."""
    
    def __init__(self, session_id: str, sock, host: str, port: int, proto: int):
        self.id = session_id
        self.socket = sock
        self.host = host
        self.port = port
        self.proto = proto
        self.created = time.time()
        self.last_active = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.requests = 0
        self.idle_count = 0
    
    @classmethod
    def create(cls, sock, host: str, port: int, proto: int) -> 'Session':
        session_id = str(uuid.uuid4())[:8]
        return cls(session_id, sock, host, port, proto)
    
    def touch(self) -> None:
        self.last_active = time.time()
        self.idle_count = 0
    
    def record_sent(self, count: int) -> None:
        self.bytes_sent += count
        self.requests += 1
    
    def record_received(self, count: int) -> None:
        self.bytes_received += count
    
    def close(self) -> None:
        try:
            self.socket.close()
        except Exception:
            pass


class SessionManager:
    """Thread-safe session manager with iteration support."""
    
    def __init__(self):
        self._sessions = {}
        self.lock = threading.Lock()
    
    def add(self, session: Session) -> None:
        with self.lock:
            self._sessions[session.id] = session
    
    def get(self, session_id: str) -> Session:
        with self.lock:
            return self._sessions.get(session_id)
    
    def remove(self, session_id: str) -> None:
        with self.lock:
            if session_id in self._sessions:
                self._sessions[session_id].close()
                del self._sessions[session_id]
    
    def get_all(self) -> dict:
        """Return a copy of all sessions (thread-safe)."""
        with self.lock:
            return dict(self._sessions)
    
    def count(self) -> int:
        """Return number of active sessions."""
        with self.lock:
            return len(self._sessions)