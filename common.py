import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet

class TunnelCrypto:
    def __init__(self, key: str):
        # Derive a proper Fernet key from PSK using SHA256
        key_bytes = hashlib.sha256(key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        self.fernet = Fernet(fernet_key)

    def encrypt(self, data: bytes) -> str:
        encrypted = self.fernet.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt(self, token: str) -> bytes:
        encrypted = base64.urlsafe_b64decode(token.encode())
        return self.fernet.decrypt(encrypted)

def generate_config_wizard(config_path, config_type="client"):
    """Interactive wizard to generate config file."""
    if os.path.exists(config_path):
        overwrite = input(f"Config {config_path} already exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            return False
    
    config = {}
    
    # PSK key
    print("\n=== Encryption Key ===")
    print("Enter a pre-shared key (or press Enter for random generated):")
    psk = input("PSK Key: ").strip()
    if not psk:
        import secrets
        psk = secrets.token_hex(16)
        print(f"Generated random PSK: {psk}")
    config["encryption_key"] = psk
    
    if config_type == "server":
        # Server config
        print("\n=== Server Configuration ===")
        listen_addr = input("Listen address [0.0.0.0:8080]: ").strip()
        config["listen"] = listen_addr if listen_addr else "0.0.0.0:8080"
        
        max_bytes = input("Max POST bytes [5242880]: ").strip()
        config["max_post_bytes"] = int(max_bytes) if max_bytes else 5242880  # 5MB
        
        timeout = input("Connection timeout in seconds [30]: ").strip()
        config["timeout"] = float(timeout) if timeout else 30
        
        cleanup_interval = input("Session cleanup interval in seconds [60]: ").strip()
        config["cleanup_interval"] = float(cleanup_interval) if cleanup_interval else 60
        
    else:
        # Client config
        print("\n=== Client Configuration ===")
        socks_addr = input("SOCKS5 listen address [127.0.0.1:1080]: ").strip()
        config["socks_listen"] = socks_addr if socks_addr else "127.0.0.1:1080"
        
        server_url = input("Server URL [http://localhost:8080/tunnel]: ").strip()
        config["server_url"] = server_url if server_url else "http://localhost:8080/tunnel"
        
        outbound_proxy = input("Outbound HTTP proxy (leave empty for none): ").strip()
        config["outbound_http_proxy"] = outbound_proxy if outbound_proxy else ""
        
        max_bytes = input("Max POST bytes [5242880]: ").strip()
        config["max_post_bytes"] = int(max_bytes) if max_bytes else 5242880
        
        batch_wait = input("Batch wait time in seconds [0.05]: ").strip()
        config["batch_wait"] = float(batch_wait) if batch_wait else 0.05
        
        heartbeat = input("Heartbeat interval in seconds [0.5]: ").strip()
        config["heartbeat_interval"] = float(heartbeat) if heartbeat else 0.5
        
        http_timeout = input("HTTP request timeout in seconds [10]: ").strip()
        config["http_timeout"] = float(http_timeout) if http_timeout else 10
        
        reconnect_delay = input("Reconnect base delay in seconds [1]: ").strip()
        config["reconnect_delay"] = float(reconnect_delay) if reconnect_delay else 1
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"\nConfiguration saved to {config_path}")
    return True