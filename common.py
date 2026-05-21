from cryptography.fernet import Fernet
import base64
import json
import uuid

class TunnelCrypto:
    def __init__(self, key: str):
        self.fernet = Fernet(key.encode())

    def encrypt(self, data: bytes) -> str:
        """Encrypt binary data and return base64 text."""
        encrypted = self.fernet.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt(self, token: str) -> bytes:
        """Decrypt base64 token back to binary."""
        encrypted = base64.urlsafe_b64decode(token.encode())
        return self.fernet.decrypt(encrypted)

def create_connect_message(target_host: str, target_port: int) -> str:
    msg = json.dumps({
        "type": "connect",
        "host": target_host,
        "port": target_port
    })
    return msg

def create_close_message() -> str:
    msg = json.dumps({"type": "close"})
    return msg
