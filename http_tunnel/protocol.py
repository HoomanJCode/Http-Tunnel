"""Protocol constants and message formatting for tunnel communication.

Message formats:
- Connect: {"type": "connect", "host": "...", "port": 443, "proto": 1}
- Ping: {"type": "ping"}
- Session data: session_id::payload
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


def create_udp_message(session_id: str, data: bytes) -> bytes:
    """Create a UDP data message: session_id::UDP:data"""
    return session_id.encode() + b"::UDP:" + data


def parse_session_message(message: bytes) -> tuple:
    """Parse session message into (session_id, data). Returns (None, None) if invalid."""
    if b'::' not in message:
        return None, None
    
    parts = message.split(b'::', 1)
    session_id = parts[0].decode('ascii', errors='ignore')
    data = parts[1] if len(parts) > 1 else b""
    
    return session_id, data


def is_tls_data(data: bytes) -> bool:
    """Detect if data is TLS encrypted (for optimization).
    
    TLS records start with content type byte:
    0x16 = Handshake, 0x17 = Application Data
    """
    if len(data) < 3:
        return False
    return data[0] in [0x16, 0x17]