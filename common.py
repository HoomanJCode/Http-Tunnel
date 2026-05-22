import json
import os
import base64
import hashlib
import logging
import time
import threading
import queue
import uuid
import zlib
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

# Compression constants
COMPRESS_NONE = 0
COMPRESS_ZLIB = 1
COMPRESS_LZ4 = 2  # Future support

def compress_data(data: bytes, method=COMPRESS_ZLIB, threshold=100) -> bytes:
    """Compress data if beneficial."""
    if method == COMPRESS_NONE or len(data) < threshold:
        return b'\x00' + data  # No compression marker
    
    if method == COMPRESS_ZLIB:
        compressed = zlib.compress(data, 6)
        if len(compressed) < len(data):
            return b'\x01' + compressed  # Compressed marker
        return b'\x00' + data  # Compression didn't help
    
    return b'\x00' + data

def decompress_data(data: bytes) -> bytes:
    """Decompress data based on marker byte."""
    if not data:
        return data
    
    marker = data[0]
    payload = data[1:]
    
    if marker == 0x00:  # No compression
        return payload
    elif marker == 0x01:  # Zlib compressed
        return zlib.decompress(payload)
    else:
        return payload  # Unknown marker, return as-is

class StreamManager:
    """Manages multiple logical streams over single physical connection."""
    def __init__(self):
        self.streams = {}
        self.lock = threading.Lock()
    
    def create_stream(self):
        """Create new stream ID."""
        stream_id = str(uuid.uuid4())[:8]
        with self.lock:
            self.streams[stream_id] = {
                'buffer': queue.Queue(),
                'created': time.time(),
                'last_active': time.time()
            }
        return stream_id
    
    def close_stream(self, stream_id):
        """Close and cleanup stream."""
        with self.lock:
            if stream_id in self.streams:
                del self.streams[stream_id]
    
    def send_data(self, stream_id, data):
        """Queue data for stream."""
        with self.lock:
            if stream_id in self.streams:
                self.streams[stream_id]['buffer'].put(data)
                self.streams[stream_id]['last_active'] = time.time()
    
    def receive_data(self, stream_id, timeout=0.1):
        """Receive data from stream buffer."""
        with self.lock:
            if stream_id in self.streams:
                try:
                    data = self.streams[stream_id]['buffer'].get(timeout=timeout)
                    self.streams[stream_id]['last_active'] = time.time()
                    return data
                except queue.Empty:
                    return None
        return None

def generate_server_config(config_path="server_config.json"):
    """Generate server configuration file."""
    if os.path.exists(config_path):
        overwrite = input(f"Config {config_path} already exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            return False
    
    config = {}
    
    print("\n=== Server Configuration Wizard ===\n")
    
    # Encryption key
    print("--- Encryption ---")
    print("Enter a pre-shared key (or press Enter for random generated):")
    psk = input("PSK Key: ").strip()
    if not psk:
        import secrets
        psk = secrets.token_hex(16)
        print(f"Generated random PSK: {psk}")
    config["encryption_key"] = psk
    
    # Listen address
    print("\n--- Network ---")
    listen_addr = input("Listen address [0.0.0.0:8080]: ").strip()
    config["listen"] = listen_addr if listen_addr else "0.0.0.0:8080"
    
    # Performance settings with defaults
    print("\n--- Performance (press Enter for defaults) ---")
    max_bytes = input("Max POST bytes [5242880]: ").strip()
    config["max_post_bytes"] = int(max_bytes) if max_bytes else 5242880
    
    tcp_timeout = input("TCP session timeout in seconds [60]: ").strip()
    config["tcp_timeout"] = float(tcp_timeout) if tcp_timeout else 60
    
    udp_timeout = input("UDP session timeout in seconds [120]: ").strip()
    config["udp_timeout"] = float(udp_timeout) if udp_timeout else 120
    
    cleanup_interval = input("Session cleanup interval in seconds [30]: ").strip()
    config["cleanup_interval"] = float(cleanup_interval) if cleanup_interval else 30
    
    # Compression settings
    compress = input("Enable compression? (Y/n) [Y]: ").strip().lower()
    config["compression"] = compress != 'n'
    
    compress_threshold = input("Compression threshold in bytes [100]: ").strip()
    config["compress_threshold"] = int(compress_threshold) if compress_threshold else 100
    
    # Logging
    print("\n--- Logging ---")
    log_level = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    config["log_level"] = log_level if log_level in ["DEBUG", "INFO", "WARNING", "ERROR"] else "INFO"
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"\n✓ Server configuration saved to {config_path}")
    return True

def generate_client_config(config_path="client_config.json"):
    """Generate client configuration file."""
    if os.path.exists(config_path):
        overwrite = input(f"Config {config_path} already exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            return False
    
    config = {}
    
    print("\n=== Client Configuration Wizard ===\n")
    
    # Encryption key
    print("--- Encryption ---")
    print("Enter a pre-shared key (or press Enter for random generated):")
    psk = input("PSK Key: ").strip()
    if not psk:
        import secrets
        psk = secrets.token_hex(16)
        print(f"Generated random PSK: {psk}")
    config["encryption_key"] = psk
    
    # SOCKS5 settings
    print("\n--- SOCKS5 Proxy ---")
    socks_addr = input("SOCKS5 listen address [127.0.0.1:1080]: ").strip()
    config["socks_listen"] = socks_addr if socks_addr else "127.0.0.1:1080"
    
    # Server connection
    print("\n--- Server Connection ---")
    server_url = input("Server URL [http://localhost:8080/tunnel]: ").strip()
    config["server_url"] = server_url if server_url else "http://localhost:8080/tunnel"
    
    outbound_proxy = input("Outbound HTTP proxy (leave empty for none): ").strip()
    config["outbound_http_proxy"] = outbound_proxy if outbound_proxy else ""
    
    # Performance settings with defaults
    print("\n--- Performance (press Enter for defaults) ---")
    max_bytes = input("Max POST bytes [5242880]: ").strip()
    config["max_post_bytes"] = int(max_bytes) if max_bytes else 5242880
    
    http_timeout = input("HTTP request timeout in seconds [30]: ").strip()
    config["http_timeout"] = float(http_timeout) if http_timeout else 30
    
    heartbeat = input("Heartbeat interval in seconds [1]: ").strip()
    config["heartbeat_interval"] = float(heartbeat) if heartbeat else 1
    
    batch_wait = input("Batch wait time in seconds [0.01]: ").strip()
    config["batch_wait"] = float(batch_wait) if batch_wait else 0.01
    
    reconnect_delay = input("Reconnect delay in seconds [0.5]: ").strip()
    config["reconnect_delay"] = float(reconnect_delay) if reconnect_delay else 0.5
    
    # Compression settings
    compress = input("Enable compression? (Y/n) [Y]: ").strip().lower()
    config["compression"] = compress != 'n'
    
    compress_threshold = input("Compression threshold in bytes [100]: ").strip()
    config["compress_threshold"] = int(compress_threshold) if compress_threshold else 100
    
    # Bypass configuration
    print("\n--- Bypass Configuration ---")
    print("Enter IP ranges to bypass tunnel (comma-separated, CIDR notation)")
    print("Examples: 192.168.0.0/16,10.0.0.0/8,127.0.0.0/8")
    bypass_input = input("Bypass ranges [127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]: ").strip()
    if bypass_input:
        config["bypass_ranges"] = [r.strip() for r in bypass_input.split(",")]
    else:
        config["bypass_ranges"] = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    
    bypass_local = input("Bypass localhost requests? (Y/n): ").strip().lower()
    config["bypass_local"] = bypass_local != 'n'
    
    bypass_private = input("Bypass all private networks? (Y/n): ").strip().lower()
    config["bypass_private"] = bypass_private != 'n'
    
    # Logging
    print("\n--- Logging ---")
    log_level = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    config["log_level"] = log_level if log_level in ["DEBUG", "INFO", "WARNING", "ERROR"] else "INFO"
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"\n✓ Client configuration saved to {config_path}")
    return True

def generate_config_wizard(config_path, config_type="client"):
    """Legacy wrapper for backward compatibility."""
    if config_type == "server":
        return generate_server_config(config_path)
    else:
        return generate_client_config(config_path)