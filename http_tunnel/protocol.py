"""Protocol constants and message formatting."""

import json

# Protocol type constants
PROTO_TCP = 1
PROTO_UDP = 2


def create_connect_message(host: str, port: int, proto: int = PROTO_TCP) -> str:
    """Create a connect request message.
    
    Args:
        host: Target hostname or IP address.
        port: Target port number.
        proto: Protocol type (PROTO_TCP or PROTO_UDP).
        
    Returns:
        JSON-encoded connect message string.
    """
    return json.dumps({
        "type": "connect",
        "host": host,
        "port": port,
        "proto": proto
    })


def create_ping_message() -> str:
    """Create a ping/health check message.
    
    Returns:
        JSON-encoded ping message string.
    """
    return json.dumps({"type": "ping"})


def create_session_message(session_id: str, data: bytes) -> bytes:
    """Create a session data message.
    
    Args:
        session_id: Session identifier.
        data: Payload data.
        
    Returns:
        Formatted message bytes: session_id::data
    """
    return session_id.encode() + b"::" + data


def create_udp_message(session_id: str, data: bytes) -> bytes:
    """Create a UDP data message.
    
    Args:
        session_id: Session identifier.
        data: UDP payload data.
        
    Returns:
        Formatted message bytes: session_id::UDP:data
    """
    return session_id.encode() + b"::UDP:" + data


def parse_session_message(message: bytes) -> tuple:
    """Parse a session message into session_id and data.
    
    Args:
        message: Raw message bytes.
        
    Returns:
        Tuple of (session_id, data) or (None, None) if invalid.
    """
    if b'::' not in message:
        return None, None
    
    parts = message.split(b'::', 1)
    session_id = parts[0].decode('ascii', errors='ignore')
    data = parts[1] if len(parts) > 1 else b""
    
    return session_id, data
