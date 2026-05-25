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
        self.logger.info(f"Cleaner started (every 10s)")
        while True:
            time.sleep(10)
            self._clean_stale()
    
    def _clean_stale(self):
        now = time.time()
        sessions = self.handler_class.sessions.get_all()
        removed = 0
        
        for sid, session in sessions.items():
            timeout = self.handler_class.udp_timeout if session.proto == PROTO_UDP else self.handler_class.tcp_timeout
            if now - session.last_active > timeout:
                try:
                    self.handler_class.sessions.remove(sid)
                    removed += 1
                except:
                    pass
        
        if removed:
            remaining = self.handler_class.sessions.count()
            self.logger.info(f"Cleaned {removed} stale ({remaining} left)")