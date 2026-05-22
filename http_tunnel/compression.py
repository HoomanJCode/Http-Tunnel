"""Compression utilities for reducing bandwidth usage."""

import zlib

# Compression method constants
COMPRESS_NONE = 0
COMPRESS_ZLIB = 1


def compress_data(data: bytes, method: int = COMPRESS_ZLIB, threshold: int = 100) -> bytes:
    """Compress data if beneficial.
    
    Args:
        data: Raw bytes to potentially compress.
        method: Compression method (COMPRESS_NONE or COMPRESS_ZLIB).
        threshold: Minimum size in bytes to attempt compression.
        
    Returns:
        Bytes with compression marker prefix (0x00 = none, 0x01 = zlib).
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
    """Decompress data based on marker byte.
    
    Args:
        data: Bytes with compression marker prefix.
        
    Returns:
        Decompressed bytes, or original if decompression fails.
    """
    if not data:
        return data
    
    marker = data[0]
    payload = data[1:]
    
    if marker == 0x00:
        return payload
    elif marker == 0x01:
        try:
            return zlib.decompress(payload)
        except zlib.error:
            return payload
    else:
        return payload
