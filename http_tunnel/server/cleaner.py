"""Session cleaner - removes stale sessions periodically."""

import threading
import time
import logging


class SessionCleaner(threading.Thread):
    """Background thread that cleans up stale sessions."""
    
    def __init__(self, handler_class, cleanup_interval: int = 30):
        super().__init__(daemon=True)
        self.handler_class = handler_class
        self.cleanup_interval = cleanup_interval
        self.logger = logging.getLogger("server.cleaner")
    
    def run(self):
        self.logger.info(f"Cleaner started ({self.cleanup_interval}s)")
        while True:
            time.sleep(10)
            self._clean_stale()
    
    def _clean_stale(self):
        now = time.time()
        with self.handler_class.sessions.lock:
            sessions = list(self.handler_class.sessions.sessions.items())
        
        removed = 0
        for sid, session in sessions:
            timeout = self.handler_class.udp_timeout if session.proto == 2 else self.handler_class.tcp_timeout
            if now - session.last_active > timeout:
                try:
                    self.handler_class.sessions.remove(sid)
                    # Also clean IP tracking
                    if hasattr(self.handler_class, '_remove_ip_session'):
                        # Find which IP this session belongs to
                        with self.handler_class.ip_lock:
                            for ip, sids in list(self.handler_class.ip_sessions.items()):
                                if sid in sids:
                                    sids.remove(sid)
                                    if not sids:
                                        del self.handler_class.ip_sessions[ip]
                                    break
                    removed += 1
                except:
                    pass
        
        if removed:
            remaining = len(self.handler_class.sessions.sessions)
            self.logger.info(f"Cleaned {removed} stale sessions ({remaining} remaining)")