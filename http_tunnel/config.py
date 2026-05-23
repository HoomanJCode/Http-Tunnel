"""Configuration management with validation, cleaning, and wizard generation.

Configuration is auto-cleaned on load:
- Invalid parameters (wrong type) are removed
- Missing optional parameters get defaults

Server and client have separate valid parameter sets.
"""

import json
import os
import secrets

# Sentinel object to distinguish required params from boolean defaults
_REQUIRED = object()

# Valid server configuration parameters with defaults
SERVER_CONFIG_PARAMS = {
    "encryption_key": _REQUIRED,   # Must be provided
    "listen": _REQUIRED,           # Must be provided
    "max_post_bytes": 5242880,     # 5MB default
    "tcp_timeout": 60,             # Session idle timeout in seconds
    "udp_timeout": 120,            # UDP session timeout in seconds
    "cleanup_interval": 30,        # Stale session check interval
    "compression": True,           # Zlib compression enabled
    "log_level": "INFO"            # Logging verbosity
}

# Valid client configuration parameters with defaults
CLIENT_CONFIG_PARAMS = {
    # Required
    "encryption_key": _REQUIRED,   # Must match server
    "socks_listen": _REQUIRED,     # SOCKS5 proxy address
    "server_url": _REQUIRED,       # Tunnel server URL
    
    # Proxy
    "outbound_http_proxy": "",     # Optional outbound proxy URL
    
    # DNS
    "dns_mode": "server",          # DNS resolution: server or local
    
    # Timing
    "http_timeout": 30,            # HTTP request timeout in seconds
    "heartbeat_interval": 1,       # Keep-alive interval (adaptive 1s-30s)
    "batch_wait": 0.01,            # Data batching delay (0=disable batching)
    "reconnect_delay": 0.5,        # Reconnection backoff base
    
    # Size limits
    "max_post_bytes": 5242880,     # 5MB default
    
    # Compression
    "compression": True,           # Zlib compression enabled
    "compress_threshold": 100,     # Minimum bytes to attempt compression
    "skip_compress_tls": True,     # Don't compress already-encrypted TLS data
    
    # Bypass
    "bypass_local": True,          # Bypass tunnel for localhost
    "bypass_ranges": [             # IP ranges to bypass (CIDR notation)
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ],
    
    # QoS
    "high_priority_ports": [22, 80, 443, 8080],  # Ports with lower batch wait
    
    # Logging
    "log_level": "INFO"            # Logging verbosity
}


def clean_config(config: dict, config_type: str = "client") -> dict:
    """Clean configuration by removing invalid params and adding defaults.
    
    Required params (marked _REQUIRED) get None if missing.
    Optional params get their default values if missing.
    """
    valid_params = SERVER_CONFIG_PARAMS if config_type == "server" else CLIENT_CONFIG_PARAMS
    cleaned = {}
    
    for param, default in valid_params.items():
        if param in config:
            cleaned[param] = config[param]
        elif default is _REQUIRED:
            cleaned[param] = None  # Required but missing
        else:
            cleaned[param] = default  # Use default
    
    return cleaned


def save_config(config_path: str, config: dict) -> None:
    """Save configuration dictionary to JSON file."""
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)


def load_and_clean_config(config_path: str, config_type: str = "client") -> dict:
    """Load config file, clean it, save if changed, return cleaned version.
    
    Prints changes made (removed/added parameters).
    """
    with open(config_path) as f:
        config = json.load(f)
    
    original_keys = set(config.keys())
    cleaned = clean_config(config, config_type)
    cleaned_keys = set(cleaned.keys())
    
    removed = original_keys - cleaned_keys
    added = cleaned_keys - original_keys
    
    if removed or added:
        if removed:
            print(f"Removed invalid parameters: {', '.join(removed)}")
        if added:
            print(f"Added missing defaults: {', '.join(added)}")
        save_config(config_path, cleaned)
        print(f"Configuration cleaned and saved to {config_path}")
    
    return cleaned


def generate_server_config(config_path: str = "server_config.json") -> bool:
    """Interactive wizard to generate server configuration file."""
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
        psk = secrets.token_hex(16)
        print(f"Generated random PSK: {psk}")
    config["encryption_key"] = psk
    
    # Network settings
    print("\n--- Network ---")
    listen_addr = input("Listen address [0.0.0.0:8080]: ").strip()
    config["listen"] = listen_addr if listen_addr else "0.0.0.0:8080"
    
    # Performance
    print("\n--- Performance (press Enter for defaults) ---")
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    _prompt_float(config, "tcp_timeout", "TCP session timeout (seconds)", 60)
    _prompt_float(config, "udp_timeout", "UDP session timeout (seconds)", 120)
    _prompt_float(config, "cleanup_interval", "Cleanup interval (seconds)", 30)
    
    compress = input("Enable compression? (Y/n) [Y]: ").strip().lower()
    config["compression"] = compress != 'n'
    
    # Logging
    print("\n--- Logging ---")
    log_level = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    config["log_level"] = log_level if log_level in ["DEBUG", "INFO", "WARNING", "ERROR"] else "INFO"
    
    config = clean_config(config, "server")
    save_config(config_path, config)
    
    print(f"\nServer configuration saved to {config_path}")
    return True


def generate_client_config(config_path: str = "client_config.json") -> bool:
    """Interactive wizard to generate client configuration file."""
    if os.path.exists(config_path):
        overwrite = input(f"Config {config_path} already exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            return False
    
    config = {}
    
    print("\n=== Client Configuration Wizard ===\n")
    
    # Encryption
    print("--- Encryption ---")
    print("Enter a pre-shared key (or press Enter for random generated):")
    psk = input("PSK Key: ").strip()
    if not psk:
        psk = secrets.token_hex(16)
        print(f"Generated random PSK: {psk}")
    config["encryption_key"] = psk
    
    # SOCKS5
    print("\n--- SOCKS5 Proxy ---")
    socks_addr = input("SOCKS5 listen address [127.0.0.1:1080]: ").strip()
    config["socks_listen"] = socks_addr if socks_addr else "127.0.0.1:1080"
    
    # Server
    print("\n--- Server Connection ---")
    server_url = input("Server URL [http://localhost:8080/tunnel]: ").strip()
    config["server_url"] = server_url if server_url else "http://localhost:8080/tunnel"
    
    outbound_proxy = input("Outbound HTTP proxy (leave empty for none): ").strip()
    config["outbound_http_proxy"] = outbound_proxy if outbound_proxy else ""
    
    # DNS
    print("\n--- DNS ---")
    dns_mode = input("DNS mode (local/server) [server]: ").strip().lower()
    config["dns_mode"] = dns_mode if dns_mode in ["local", "server"] else "server"
    
    # Timing
    print("\n--- Timing (press Enter for defaults) ---")
    _prompt_float(config, "http_timeout", "HTTP timeout (seconds)", 30)
    _prompt_float(config, "heartbeat_interval", "Heartbeat interval (seconds)", 1)
    _prompt_float(config, "batch_wait", "Batch wait (seconds, 0=disable)", 0.01)
    _prompt_float(config, "reconnect_delay", "Reconnect delay (seconds)", 0.5)
    
    # Size
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    
    # Compression
    print("\n--- Compression ---")
    compress = input("Enable compression? (Y/n) [Y]: ").strip().lower()
    config["compression"] = compress != 'n'
    if config["compression"]:
        _prompt_int(config, "compress_threshold", "Compression threshold (bytes)", 100)
        skip_tls = input("Skip compression for TLS data? (Y/n) [Y]: ").strip().lower()
        config["skip_compress_tls"] = skip_tls != 'n'
    
    # Bypass
    print("\n--- Bypass ---")
    bypass_local = input("Bypass localhost? (Y/n) [Y]: ").strip().lower()
    config["bypass_local"] = bypass_local != 'n'
    
    bypass_input = input("Bypass IP ranges (comma-separated CIDR, Enter for defaults): ").strip()
    if bypass_input:
        config["bypass_ranges"] = [r.strip() for r in bypass_input.split(",")]
    else:
        config["bypass_ranges"] = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    
    # QoS
    print("\n--- QoS ---")
    qos_input = input("High priority ports (comma-separated, Enter for defaults): ").strip()
    if qos_input:
        config["high_priority_ports"] = [int(p.strip()) for p in qos_input.split(",")]
    else:
        config["high_priority_ports"] = [22, 80, 443, 8080]
    
    # Logging
    print("\n--- Logging ---")
    log_level = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    config["log_level"] = log_level if log_level in ["DEBUG", "INFO", "WARNING", "ERROR"] else "INFO"
    
    config = clean_config(config, "client")
    save_config(config_path, config)
    
    print(f"\nClient configuration saved to {config_path}")
    return True


def _prompt_int(config: dict, key: str, description: str, default: int) -> None:
    value = input(f"{description} [{default}]: ").strip()
    config[key] = int(value) if value else default


def _prompt_float(config: dict, key: str, description: str, default: float) -> None:
    value = input(f"{description} [{default}]: ").strip()
    config[key] = float(value) if value else default