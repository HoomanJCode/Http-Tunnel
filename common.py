import json
import os
import base64
import hashlib
import struct
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

def generate_config_wizard(config_path, config_type="client"):
    if os.path.exists(config_path):
        overwrite = input(f"Config {config_path} already exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            return False
    
    config = {}
    
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
        
        max_bytes = input("Max POST bytes [5242880]: ").strip()
        config["max_post_bytes"] = int(max_bytes) if max_bytes else 5242880
        
        timeout = input("Connection timeout in seconds [60]: ").strip()
        config["timeout"] = float(timeout) if timeout else 60
        
        cleanup_interval = input("Session cleanup interval in seconds [120]: ").strip()
        config["cleanup_interval"] = float(cleanup_interval) if cleanup_interval else 120
        
        workers = input("Thread pool workers [10]: ").strip()
        config["workers"] = int(workers) if workers else 10
    else:
        print("\n=== Client Configuration ===")
        socks_addr = input("SOCKS5 listen address [127.0.0.1:1080]: ").strip()
        config["socks_listen"] = socks_addr if socks_addr else "127.0.0.1:1080"
        
        server_url = input("Server URL [http://localhost:8080/tunnel]: ").strip()
        config["server_url"] = server_url if server_url else "http://localhost:8080/tunnel"
        
        outbound_proxy = input("Outbound HTTP proxy (leave empty for none): ").strip()
        config["outbound_http_proxy"] = outbound_proxy if outbound_proxy else ""
        
        max_bytes = input("Max POST bytes [5242880]: ").strip()
        config["max_post_bytes"] = int(max_bytes) if max_bytes else 5242880
        
        batch_wait = input("Batch wait time in seconds [0.02]: ").strip()
        config["batch_wait"] = float(batch_wait) if batch_wait else 0.02
        
        heartbeat = input("Heartbeat interval in seconds [0.3]: ").strip()
        config["heartbeat_interval"] = float(heartbeat) if heartbeat else 0.3
        
        http_timeout = input("HTTP request timeout in seconds [30]: ").strip()
        config["http_timeout"] = float(http_timeout) if http_timeout else 30
        
        reconnect_delay = input("Reconnect base delay in seconds [0.5]: ").strip()
        config["reconnect_delay"] = float(reconnect_delay) if reconnect_delay else 0.5
        
        udp_timeout = input("UDP session timeout in seconds [30]: ").strip()
        config["udp_timeout"] = float(udp_timeout) if udp_timeout else 30
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"\nConfiguration saved to {config_path}")
    return True

class UDPPacket:
    """Helper class for UDP packet encoding/decoding."""
    @staticmethod
    def encode(data: bytes, addr: tuple) -> bytes:
        """Encode UDP packet with SOCKS5 UDP header."""
        # SOCKS5 UDP header: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT | DATA
        host, port = addr
        # Determine address type
        try:
            ip_bytes = socket.inet_aton(host)
            header = b'\x00\x00\x00\x01' + ip_bytes  # IPv4
        except OSError:
            # Domain name
            host_bytes = host.encode()
            header = b'\x00\x00\x00\x03' + bytes([len(host_bytes)]) + host_bytes
        
        header += struct.pack('!H', port)
        return header + data
    
    @staticmethod
    def decode(packet: bytes):
        """Decode SOCKS5 UDP packet, returns (data, addr_tuple)."""
        if len(packet) < 10:
            return None, None
        
        frag = packet[2]
        atyp = packet[3]
        
        pos = 4
        if atyp == 1:  # IPv4
            host = socket.inet_ntoa(packet[pos:pos+4])
            pos += 4
        elif atyp == 3:  # Domain
            length = packet[pos]
            pos += 1
            host = packet[pos:pos+length].decode()
            pos += length
        elif atyp == 4:  # IPv6
            host = socket.inet_ntop(socket.AF_INET6, packet[pos:pos+16])
            pos += 16
        else:
            return None, None
        
        port = struct.unpack('!H', packet[pos:pos+2])[0]
        data = packet[pos+2:]
        return data, (host, port)