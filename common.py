import json
import os
import base64
import hashlib
import logging
from cryptography.fernet import Fernet

class TunnelCrypto:
    def __init__(self, key: str):
        key_bytes = hashlib.sha256(key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        self.fernet = Fernet(fernet_key)

    def encrypt(self, data: bytes) -> str:
        encrypted = self.fernet.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt(self, token: str) -> bytes:
        encrypted = base64.urlsafe_b64decode(token.encode())
        return self.fernet.decrypt(encrypted)

def setup_logging(config, name="tunnel"):
    """Setup logging based on config."""
    log_level = config.get("log_level", "INFO").upper()
    level = getattr(logging, log_level, logging.INFO)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    return logging.getLogger(name)

# Protocol constants
PROTO_TCP = 1
PROTO_UDP = 2

def generate_config_wizard(config_path, config_type="client"):
    if os.path.exists(config_path):
        overwrite = input(f"Config {config_path} already exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            return False
    
    config = {}
    
    # Default values
    defaults = {
        "log_level": "INFO",
        "max_post_bytes": 5242880,
        "batch_wait": 0.01,
        "reconnect_delay": 0.5,
        "http_timeout": 30,
        "heartbeat_interval": 1,
        "timeout": 60,
        "udp_timeout": 120,
        "cleanup_interval": 30
    }
    config.update(defaults)
    
    print("\n=== Encryption Key ===")
    print("Enter a pre-shared key (or press Enter for random generated):")
    psk = input("PSK Key: ").strip()
    if not psk:
        import secrets
        psk = secrets.token_hex(16)
        print(f"Generated random PSK: {psk}")
    config["encryption_key"] = psk
    
    if config_type == "server":
        print("\n=== Server Configuration ===")
        listen_addr = input("Listen address [0.0.0.0:8080]: ").strip()
        config["listen"] = listen_addr if listen_addr else "0.0.0.0:8080"
        
        print(f"\nUsing default values:")
        print(f"  TCP timeout: {config['timeout']}s")
        print(f"  UDP timeout: {config['udp_timeout']}s")
        print(f"  Max POST: {config['max_post_bytes']} bytes")
        print(f"  Cleanup interval: {config['cleanup_interval']}s")
        print(f"  Log level: {config['log_level']}")
    else:
        print("\n=== Client Configuration ===")
        socks_addr = input("SOCKS5 listen address [127.0.0.1:1080]: ").strip()
        config["socks_listen"] = socks_addr if socks_addr else "127.0.0.1:1080"
        
        server_url = input("Server URL [http://localhost:8080/tunnel]: ").strip()
        config["server_url"] = server_url if server_url else "http://localhost:8080/tunnel"
        
        outbound_proxy = input("Outbound HTTP proxy (leave empty for none): ").strip()
        config["outbound_http_proxy"] = outbound_proxy if outbound_proxy else ""
        
        print(f"\nUsing default values:")
        print(f"  HTTP timeout: {config['http_timeout']}s")
        print(f"  Heartbeat: {config['heartbeat_interval']}s")
        print(f"  Max POST: {config['max_post_bytes']} bytes")
        print(f"  Batch wait: {config['batch_wait']}s")
        print(f"  Reconnect delay: {config['reconnect_delay']}s")
        print(f"  Log level: {config['log_level']}")
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"\nConfiguration saved to {config_path}")
    return True