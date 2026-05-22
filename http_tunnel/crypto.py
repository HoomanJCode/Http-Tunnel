"""Encryption utilities for tunnel traffic."""

import base64
import hashlib
from cryptography.fernet import Fernet


class TunnelCrypto:
    """Handles encryption/decryption of tunnel data using Fernet symmetric encryption."""
    
    def __init__(self, key: str):
        """Initialize with a pre-shared key.
        
        Args:
            key: Pre-shared key string, hashed with SHA256 to derive Fernet key.
        """
        key_bytes = hashlib.sha256(key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        self.fernet = Fernet(fernet_key)

    def encrypt(self, data: bytes) -> str:
        """Encrypt binary data and return base64-encoded string.
        
        Args:
            data: Raw bytes to encrypt.
            
        Returns:
            Base64-encoded encrypted string.
        """
        encrypted = self.fernet.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt(self, token: str) -> bytes:
        """Decrypt base64-encoded string back to bytes.
        
        Args:
            token: Base64-encoded encrypted string.
            
        Returns:
            Decrypted bytes.
        """
        encrypted = base64.urlsafe_b64decode(token.encode())
        return self.fernet.decrypt(encrypted)
