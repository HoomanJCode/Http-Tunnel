"""Protocol constants and message formatting for tunnel communication.

Message formats:
- Connect: {"type": "connect", "host": "...", "port": 443, "proto": 1}
- Ping: {"type": "ping"}
- Session data: session_id::payload
- Stream data: session_id::stream_id::payload  (NEW - for multiplexed streams)
- UDP data: session_id::UDP:payload
- Close: session_id::CLOSE
- Heartbeat: session_id::HEARTBEAT
"""

import json

# Protocol type constants
PROTO_TCP = 1
PROTO_UDP = 2

# Session message types
MSG_CLOSE = b"CLOSE"
MSG_HEARTBEAT = b"HEARTBEAT"

# Maximum concurrent streams per connection
MAX_STREAMS = 8


def create_connect_message(host: str, port: int, proto: int = PROTO_TCP) -> str:
    """Create a connect request message for establishing tunnel session."""
    return json.dumps({
        "type": "connect",
        "host": host,
        "port": port,
        "proto": proto
    })


def create_ping_message() -> str:
    """Create a ping/health check message."""
    return json.dumps({"type": "ping"})


def create_session_message(session_id: str, data: bytes) -> bytes:
    """Create a session data message: session_id::data"""
    return session_id.encode() + b"::" + data


def create_stream_message(session_id: str, stream_id: str, data: bytes) -> bytes:
    """Create a stream data message: session_id::stream_id::data
    
    Used when multiple SOCKS5 connections share one tunnel session.
    The stream_id routes data to the correct SOCKS5 connection.
    """
    return session_id.encode() + b"::" + stream_id.encode() + b"::" + data


def create_udp_message(session_id: str, data: bytes) -> bytes:
    """Create a UDP data message: session_id::UDP:data"""
    return session_id.encode() + b"::UDP:" + data


def parse_session_message(message: bytes) -> tuple:
    """Parse session message into (session_id, data).
    
    Also handles stream messages: (session_id, stream_id::data)
    Returns (None, None) if invalid.
    """
    if b'::' not in message:
        return None, None, None
    
    parts = message.split(b'::', 2)  # Max 3 parts
    session_id = parts[0].decode('ascii', errors='ignore')
    
    if len(parts) == 2:
        # Old format: session_id::data
        return session_id, None, parts[1]
    elif len(parts) == 3:
        # New format: session_id::stream_id::data
        stream_id = parts[1].decode('ascii', errors='ignore')
        return session_id, stream_id, parts[2]
    
    return None, None, None


def is_tls_data(data: bytes) -> bool:
    """Detect if data is TLS encrypted (for optimization).
    
    TLS records start with content type byte:
    0x16 = Handshake, 0x17 = Application Data
    """
    if len(data) < 3:
        return False
    return data[0] in [0x16, 0x17]
    
def is_websocket_upgrade(data: bytes) -> bool:
    """Detect if data contains a WebSocket upgrade request."""
    return b"Upgrade: websocket" in data or b"upgrade: websocket" in data or b"Upgrade: WebSocket" in data

def is_websocket_established(first_byte: int) -> bool:
    """WebSocket frames start with 0x81 (text), 0x82 (binary), 0x88 (close), 0x89 (ping), 0x8A (pong)."""
    return first_byte in (0x81, 0x82, 0x88, 0x89, 0x8A)