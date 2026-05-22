"""Stream manager for multiplexing multiple logical streams."""

import queue
import threading
import time
import uuid


class StreamManager:
    """Manages multiple logical streams over a single physical connection."""
    
    def __init__(self):
        self.streams = {}
        self.lock = threading.Lock()
    
    def create_stream(self) -> str:
        """Create a new stream and return its ID."""
        stream_id = str(uuid.uuid4())[:8]
        with self.lock:
            self.streams[stream_id] = {
                'buffer': queue.Queue(),
                'created': time.time(),
                'last_active': time.time()
            }
        return stream_id
    
    def close_stream(self, stream_id: str) -> None:
        """Close and cleanup a stream."""
        with self.lock:
            if stream_id in self.streams:
                del self.streams[stream_id]
    
    def send_data(self, stream_id: str, data: bytes) -> None:
        """Queue data for a stream."""
        with self.lock:
            if stream_id in self.streams:
                self.streams[stream_id]['buffer'].put(data)
                self.streams[stream_id]['last_active'] = time.time()
    
    def receive_data(self, stream_id: str, timeout: float = 0.1) -> bytes:
        """Receive data from a stream buffer."""
        with self.lock:
            if stream_id in self.streams:
                try:
                    data = self.streams[stream_id]['buffer'].get(timeout=timeout)
                    self.streams[stream_id]['last_active'] = time.time()
                    return data
                except queue.Empty:
                    return None
        return None
    
    def get_active_count(self) -> int:
        """Get number of active streams."""
        with self.lock:
            return len(self.streams)
