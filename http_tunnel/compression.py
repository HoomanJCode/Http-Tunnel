"""Compression utilities for reducing bandwidth usage.

Uses zlib with marker bytes to indicate compression status:
- 0x00: No compression (data too small or compression didn't help)
- 0x01: Zlib compressed data
"""

import zlib

# Compression method constants
COMPRESS_NONE = 0
COMPRESS_ZLIB = 1


def compress_data(data: bytes, method: int = COMPRESS_ZLIB, threshold: int = 100) -> bytes:
    """Compress data if beneficial. Adds marker byte prefix.
    
    Skips compression for data smaller than threshold or if compression doesn't reduce size.
    """
    if method == COMPRESS_NONE or len(data) < threshold:
        return b'\x00' + data
    
    if method == COMPRESS_ZLIB:
        compressed = zlib.compress(data, 6)
        if len(compressed) < len(data):
            return b'\x01' + compressed
        return b'\x00' + data
    
    return b'\x00' + data


def decompress_data(data: bytes) -> bytes:
    """Decompress data based on marker byte prefix."""
    if not data:
        return data
    
    marker = data[0]
    payload = data[1:]
    
    if marker == 0x00:  # Uncompressed
        return payload
    elif marker == 0x01:  # Zlib compressed
        try:
            return zlib.decompress(payload)
        except zlib.error:
            return payload  # Return as-is on corruption
    else:
        return payload  # Unknown marker


def should_compress(content_type: bytes, data: bytes) -> bool:
    """Determine if data should be compressed based on content analysis.
    
    Skip compression for already-compressed formats (images, video, encrypted TLS).
    """
    # Skip if already encrypted (TLS data)
    if len(data) > 0 and data[0] in [0x16, 0x17]:  # TLS handshake/application data
        return False
    
    # Skip binary/compressed content types
    skip_types = [b'image/', b'video/', b'audio/', b'application/octet-stream']
    for skip in skip_types:
        if skip in content_type:
            return False
    
    return True