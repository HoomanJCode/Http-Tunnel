"""Configuration management with validation, cleaning, and wizard generation.

Configuration is auto-cleaned on load:
- Invalid parameters (wrong type) are removed
- Missing optional parameters get defaults
- Required parameters without values are set to None

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
    "tcp_timeout": 60,             # Session idle timeout
    "udp_timeout": 120,            # UDP session timeout
    "cleanup_interval": 30,        # Stale session check interval
    "compression": True,           # Zlib compression enabled
    "log_level": "INFO"            # Logging verbosity
}

# Valid client configuration parameters with defaults
CLIENT_CONFIG_PARAMS = {
    "encryption_key": _REQUIRED,   # Must match server
    "socks_listen": _REQUIRED,     # SOCKS5 proxy address
    "server_url": _REQUIRED,       # Tunnel server URL
    "outbound_http_proxy": "",     # Optional outbound proxy
    "max_post_bytes": 5242880,     # 5MB default
    "http_timeout": 30,            # HTTP request timeout
    "heartbeat_interval": 1,       # Keep-alive interval (adaptive)
    "batch_wait": 0.01,            # Data batching delay
    "reconnect_delay": 0.5,        # Reconnection backoff base
    "compression": True,           # Zlib compression enabled
    "bypass_local": True,          # Bypass tunnel for localhost
    "dns_mode": "server",          # DNS resolution: server or local
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
    
    # Performance settings
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
    
    # Encryption key
    print("--- Encryption ---")
    print("Enter a pre-shared key (or press Enter for random generated):")
    psk = input("PSK Key: ").strip()
    if not psk:
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
    
    # DNS mode (important for censorship bypass)
    print("\n--- DNS Configuration ---")
    print("'server' mode prevents DNS leaks by resolving on server")
    dns_mode = input("DNS resolution mode (local/server) [server]: ").strip().lower()
    config["dns_mode"] = dns_mode if dns_mode in ["local", "server"] else "server"
    
    # Performance
    print("\n--- Performance (press Enter for defaults) ---")
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    _prompt_float(config, "http_timeout", "HTTP request timeout (seconds)", 30)
    _prompt_float(config, "heartbeat_interval", "Heartbeat interval (seconds)", 1)
    _prompt_float(config, "batch_wait", "Batch wait time (seconds)", 0.01)
    _prompt_float(config, "reconnect_delay", "Reconnect delay (seconds)", 0.5)
    
    compress = input("Enable compression? (Y/n) [Y]: ").strip().lower()
    config["compression"] = compress != 'n'
    
    # Bypass
    print("\n--- Bypass ---")
    bypass_local = input("Bypass localhost requests? (Y/n) [Y]: ").strip().lower()
    config["bypass_local"] = bypass_local != 'n'
    
    # Logging
    print("\n--- Logging ---")
    log_level = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    config["log_level"] = log_level if log_level in ["DEBUG", "INFO", "WARNING", "ERROR"] else "INFO"
    
    config = clean_config(config, "client")
    save_config(config_path, config)
    
    print(f"\nClient configuration saved to {config_path}")
    return True


def _prompt_int(config: dict, key: str, description: str, default: int) -> None:
    """Prompt for integer configuration value."""
    value = input(f"{description} [{default}]: ").strip()
    config[key] = int(value) if value else default


def _prompt_float(config: dict, key: str, description: str, default: float) -> None:
    """Prompt for float configuration value."""
    value = input(f"{description} [{default}]: ").strip()
    config[key] = float(value) if value else default