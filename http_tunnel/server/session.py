"""Session management for tunnel connections."""

import time
import uuid


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
        """Create a new session with generated ID."""
        session_id = str(uuid.uuid4())[:8]
        return cls(session_id, sock, host, port, proto)
    
    def touch(self) -> None:
        """Update last active timestamp and reset idle count."""
        self.last_active = time.time()
        self.idle_count = 0
    
    def record_sent(self, count: int) -> None:
        """Record bytes sent to destination."""
        self.bytes_sent += count
        self.requests += 1
    
    def record_received(self, count: int) -> None:
        """Record bytes received from destination."""
        self.bytes_received += count
    
    def increment_idle(self) -> None:
        """Increment idle counter."""
        self.idle_count += 1
    
    def is_stale(self, timeout: float) -> bool:
        """Check if session has been idle too long."""
        age = time.time() - self.last_active
        return age > timeout and self.idle_count > 3
    
    def close(self) -> None:
        """Close the session socket."""
        try:
            self.socket.close()
        except Exception:
            pass


class SessionManager:
    """Thread-safe session manager."""
    
    def __init__(self):
        self.sessions = {}
        self.lock = __import__('threading').Lock()
    
    def add(self, session: Session) -> None:
        """Add a session."""
        with self.lock:
            self.sessions[session.id] = session
    
    def get(self, session_id: str) -> Session:
        """Get a session by ID."""
        with self.lock:
            return self.sessions.get(session_id)
    
    def remove(self, session_id: str) -> None:
        """Remove and close a session."""
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].close()
                del self.sessions[session_id]
    
    def get_stale_sessions(self, tcp_timeout: float, udp_timeout: float) -> list:
        """Get list of stale sessions."""
        stale = []
        with self.lock:
            now = time.time()
            for session in self.sessions.values():
                timeout = udp_timeout if session.proto == 2 else tcp_timeout  # PROTO_UDP = 2
                if session.is_stale(timeout):
                    stale.append(session)
        return stale
    
    def touch(self, session_id: str) -> None:
        """Update session activity."""
        session = self.get(session_id)
        if session:
            session.touch()
