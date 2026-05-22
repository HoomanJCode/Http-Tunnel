"""Session cleaner - removes stale sessions periodically."""

import threading
import time
import logging

from http_tunnel.protocol import PROTO_UDP


class SessionCleaner(threading.Thread):
    """Background thread that cleans up stale sessions."""
    
    def __init__(self, handler_class, cleanup_interval: int = 30):
        super().__init__(daemon=True)
        self.handler_class = handler_class
        self.cleanup_interval = cleanup_interval
        self.logger = logging.getLogger("server.cleaner")
    
    def run(self):
        """Main cleaner loop."""
        self.logger.info(f"Cleaner started ({self.cleanup_interval}s)")
        while True:
            time.sleep(self.cleanup_interval)
            self._clean_stale_sessions()
    
    def _clean_stale_sessions(self):
        """Find and remove stale sessions."""
        stale = self.handler_class.sessions.get_stale_sessions(
            self.handler_class.tcp_timeout,
            self.handler_class.udp_timeout
        )
        
        for session in stale:
            age = time.time() - session.last_active
            self.logger.info(
                f"Clean session {session.id} "
                f"(idle {age:.0f}s, {session.requests} req)"
            )
            self.handler_class.sessions.remove(session.id)
