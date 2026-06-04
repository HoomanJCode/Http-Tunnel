"""Configuration management with validation, cleaning, and wizard generation."""

import json
import os
import secrets

_REQUIRED = object()

SERVER_CONFIG_PARAMS = {
    "encryption_key": _REQUIRED,
    "listen": _REQUIRED,
    "max_post_bytes": 5242880,
    "tcp_timeout": 60,
    "udp_timeout": 120,
    "connect_timeout": 8,
    "cleanup_interval": 30,
    "recv_buffer": 131072,
    "send_buffer": 131072,
    "read_chunk": 65536,
    "read_timeout": 0.01,
    "read_extend": 0.03,
    "udp_read_timeout": 0.3,       # UDP response wait time
    "log_level": "INFO"
}

CLIENT_CONFIG_PARAMS = {
    # Required
    "encryption_key": _REQUIRED,
    "socks_listen": _REQUIRED,
    "server_url": _REQUIRED,
    
    # Proxy
    "outbound_http_proxy": "",
    
    # DNS
    "dns_mode": "server",
    
    # Timeouts
    "http_timeout": 45,
    "connect_timeout": 8,
    "heartbeat_interval": 1,
    "heartbeat_max": 15,
    "batch_wait": 0.01,
    "reconnect_delay": 0.5,
    
    # Limits
    "max_post_bytes": 5242880,
    
    # Routing
    "route_tls": "tunnel",
    "route_http": "tunnel",
    "route_other": "tunnel",
    
    # Performance
    "recv_chunk": 65536,
    "fast_drain_threshold": 32768,
    "fast_drain_interval": 0.05,
    "http_pool_size": 30,
    
    # Bypass
    "bypass_local": True,
    "bypass_ranges": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    
    # QoS
    "high_priority_ports": [22, 80, 443, 8080],
    
    # Logging
    "log_level": "INFO"
}


def clean_config(config: dict, config_type: str = "client") -> dict:
    valid_params = SERVER_CONFIG_PARAMS if config_type == "server" else CLIENT_CONFIG_PARAMS
    cleaned = {}
    for param, default in valid_params.items():
        if param in config:
            cleaned[param] = config[param]
        elif default is _REQUIRED:
            cleaned[param] = None
        else:
            cleaned[param] = default
    return cleaned


def save_config(config_path: str, config: dict) -> None:
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)


def load_and_clean_config(config_path: str, config_type: str = "client") -> dict:
    with open(config_path) as f:
        config = json.load(f)
    original_keys = set(config.keys())
    cleaned = clean_config(config, config_type)
    cleaned_keys = set(cleaned.keys())
    removed = original_keys - cleaned_keys
    added = cleaned_keys - original_keys
    if removed or added:
        if removed:
            print(f"Removed: {', '.join(removed)}")
        if added:
            print(f"Added defaults: {', '.join(added)}")
        save_config(config_path, cleaned)
        print(f"Config cleaned: {config_path}")
    return cleaned


def generate_server_config(config_path: str = "server_config.json") -> bool:
    if os.path.exists(config_path):
        if input(f"Config {config_path} exists. Overwrite? (y/N): ").lower() != 'y':
            return False
    config = {}
    print("\n=== Server Configuration ===\n")
    print("Encryption Key (Enter for random):")
    psk = input("PSK Key: ").strip()
    if not psk:
        psk = secrets.token_hex(16)
        print(f"Generated: {psk}")
    config["encryption_key"] = psk
    print("\nNetwork:")
    config["listen"] = input("Listen address [0.0.0.0:8080]: ").strip() or "0.0.0.0:8080"
    print("\nTimeouts:")
    _prompt_float(config, "connect_timeout", "TCP connect timeout (s)", 8)
    _prompt_float(config, "tcp_timeout", "TCP idle timeout (s)", 60)
    _prompt_float(config, "udp_timeout", "UDP idle timeout (s)", 120)
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    _prompt_float(config, "cleanup_interval", "Cleanup interval (s)", 30)
    _prompt_float(config, "udp_read_timeout", "UDP read timeout (s)", 0.3)
    print("\nSocket Buffers:")
    _prompt_int(config, "recv_buffer", "Receive buffer (bytes)", 131072)
    _prompt_int(config, "send_buffer", "Send buffer (bytes)", 131072)
    _prompt_int(config, "read_chunk", "Read chunk (bytes)", 65536)
    _prompt_float(config, "read_timeout", "Read timeout (s)", 0.01)
    _prompt_float(config, "read_extend", "Read extend (s)", 0.03)
    print("\nLogging:")
    config["log_level"] = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper() or "INFO"
    config = clean_config(config, "server")
    save_config(config_path, config)
    print(f"\nSaved: {config_path}")
    return True


def generate_client_config(config_path: str = "client_config.json") -> bool:
    if os.path.exists(config_path):
        if input(f"Config {config_path} exists. Overwrite? (y/N): ").lower() != 'y':
            return False
    config = {}
    print("\n=== Client Configuration ===\n")
    print("Encryption Key (Enter for random):")
    psk = input("PSK Key: ").strip()
    if not psk:
        psk = secrets.token_hex(16)
        print(f"Generated: {psk}")
    config["encryption_key"] = psk
    
    print("\nSOCKS5/HTTP Proxy:")
    config["socks_listen"] = input("Listen address [127.0.0.1:1080]: ").strip() or "127.0.0.1:1080"
    
    print("\nServer:")
    config["server_url"] = input("Server URL [http://localhost:8080/tunnel]: ").strip() or "http://localhost:8080/tunnel"
    config["outbound_http_proxy"] = input("Outbound proxy (empty=none): ").strip()
    
    print("\nDNS:")
    config["dns_mode"] = input("DNS mode (local/server) [server]: ").strip().lower() or "server"
    
    print("\nRouting (direct | proxy | tunnel):")
    config["route_tls"] = input("TLS [tunnel]: ").strip().lower() or "tunnel"
    config["route_http"] = input("HTTP [tunnel]: ").strip().lower() or "tunnel"
    config["route_other"] = input("Other [tunnel]: ").strip().lower() or "tunnel"
    
    print("\nTimeouts:")
    _prompt_float(config, "connect_timeout", "TCP connect timeout (s)", 8)
    _prompt_float(config, "http_timeout", "HTTP timeout (s)", 45)
    _prompt_float(config, "heartbeat_interval", "Heartbeat (s)", 1)
    _prompt_float(config, "heartbeat_max", "Max heartbeat backoff (s)", 15)
    _prompt_float(config, "batch_wait", "Batch wait (s, 0=instant)", 0.01)
    _prompt_float(config, "reconnect_delay", "Reconnect delay (s)", 0.5)
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    
    print("\nPerformance:")
    _prompt_int(config, "recv_chunk", "Recv chunk (bytes)", 65536)
    _prompt_int(config, "fast_drain_threshold", "Fast drain threshold (bytes)", 32768)
    _prompt_float(config, "fast_drain_interval", "Fast drain interval (s)", 0.05)
    _prompt_int(config, "http_pool_size", "HTTP session pool size", 30)
    
    print("\nBypass:")
    config["bypass_local"] = input("Bypass localhost? (Y/n) [Y]: ").strip().lower() != 'n'
    bypass_input = input("Bypass CIDRs (comma, Enter=defaults): ").strip()
    config["bypass_ranges"] = [r.strip() for r in bypass_input.split(",")] if bypass_input else ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    
    print("\nQoS:")
    qos_input = input("Priority ports (comma, Enter=defaults): ").strip()
    config["high_priority_ports"] = [int(p.strip()) for p in qos_input.split(",")] if qos_input else [22, 80, 443, 8080]
    
    print("\nLogging:")
    config["log_level"] = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper() or "INFO"
    
    config = clean_config(config, "client")
    save_config(config_path, config)
    print(f"\nSaved: {config_path}")
    return True


def _prompt_int(config: dict, key: str, desc: str, default: int):
    v = input(f"{desc} [{default}]: ").strip()
    config[key] = int(v) if v else default


def _prompt_float(config: dict, key: str, desc: str, default: float):
    v = input(f"{desc} [{default}]: ").strip()
    config[key] = float(v) if v else default
    
# ─── .env Support (added for non-interactive deployment) ───
def _env(key, default=None, cast=str):
    """Get value from environment or .env file."""
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return cast(val)
    except (ValueError, TypeError):
        return default


def _load_dotenv():
    """Load .env file if it exists."""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '.env')
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


# Load .env on import
_load_dotenv()

# Server config from .env (falls back to defaults)
SERVER_CONFIG = {
    'encryption_key': _env('ENCRYPTION_KEY', secrets.token_hex(16)),
    'listen_host': _env('LISTEN_HOST', '0.0.0.0'),
    'listen_port': _env('LISTEN_PORT', 8080, int),
    'max_post_bytes': _env('MAX_POST_BYTES', 5242880, int),
    'tcp_timeout': _env('TCP_TIMEOUT', 60, float),
    'udp_timeout': _env('UDP_TIMEOUT', 120, float),
    'connect_timeout': _env('CONNECT_TIMEOUT', 8, float),
    'cleanup_interval': _env('CLEANUP_INTERVAL', 30, float),
    'recv_buffer': _env('RECV_BUFFER', 131072, int),
    'send_buffer': _env('SEND_BUFFER', 131072, int),
    'read_chunk': _env('READ_CHUNK', 65536, int),
    'read_timeout': _env('READ_TIMEOUT', 0.01, float),
    'read_extend': _env('READ_EXTEND', 0.03, float),
    'udp_read_timeout': _env('UDP_READ_TIMEOUT', 0.3, float),
    'log_level': _env('LOG_LEVEL', 'INFO'),
}

# Client config from .env (falls back to defaults)
CLIENT_CONFIG = {
    'encryption_key': _env('ENCRYPTION_KEY', secrets.token_hex(16)),
    'socks_listen_host': _env('SOCKS_LISTEN_HOST', '127.0.0.1'),
    'socks_listen_port': _env('SOCKS_LISTEN_PORT', 1080, int),
    'server_url': _env('SERVER_URL', 'http://localhost:8080/tunnel'),
    'outbound_proxy': _env('OUTBOUND_PROXY', ''),
    'dns_mode': _env('DNS_MODE', 'server'),
    'http_timeout': _env('HTTP_TIMEOUT', 45, float),
    'connect_timeout': _env('CONNECT_TIMEOUT', 8, float),
    'heartbeat_interval': _env('HEARTBEAT_INTERVAL', 1, float),
    'heartbeat_max': _env('HEARTBEAT_MAX', 15, float),
    'batch_wait': _env('BATCH_WAIT', 0.01, float),
    'reconnect_delay': _env('RECONNECT_DELAY', 0.5, float),
    'max_post_bytes': _env('MAX_POST_BYTES', 5242880, int),
    'route_tls': _env('ROUTE_TLS', 'tunnel'),
    'route_http': _env('ROUTE_HTTP', 'tunnel'),
    'route_other': _env('ROUTE_OTHER', 'tunnel'),
    'recv_chunk': _env('RECV_CHUNK', 65536, int),
    'fast_drain_threshold': _env('FAST_DRAIN_THRESHOLD', 32768, int),
    'fast_drain_interval': _env('FAST_DRAIN_INTERVAL', 0.05, float),
    'http_pool_size': _env('HTTP_POOL_SIZE', 30, int),
    'bypass_local': _env('BYPASS_LOCAL', True, lambda x: x.lower() in ('true', '1', 'yes', 'y', 'on')),
    'bypass_ranges': _env('BYPASS_RANGES', '127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16', lambda x: [v.strip() for v in x.split(',')]),
    'high_priority_ports': _env('HIGH_PRIORITY_PORTS', '22,80,443,8080', lambda x: [int(v.strip()) for v in x.split(',')]),
    'log_level': _env('LOG_LEVEL', 'INFO'),
}