"""Configuration management with validation and cleaning."""

import json
import os
import secrets

# Sentinel for required parameters
_REQUIRED = object()

# Valid server configuration parameters with defaults
SERVER_CONFIG_PARAMS = {
    "encryption_key": _REQUIRED,
    "listen": _REQUIRED,
    "max_post_bytes": 5242880,
    "tcp_timeout": 60,
    "udp_timeout": 120,
    "cleanup_interval": 30,
    "compression": True,
    "log_level": "INFO"
}

# Valid client configuration parameters with defaults
CLIENT_CONFIG_PARAMS = {
    "encryption_key": _REQUIRED,
    "socks_listen": _REQUIRED,
    "server_url": _REQUIRED,
    "outbound_http_proxy": "",
    "max_post_bytes": 5242880,
    "http_timeout": 30,
    "heartbeat_interval": 1,
    "batch_wait": 0.01,
    "reconnect_delay": 0.5,
    "compression": True,
    "bypass_local": True,
    "dns_mode": "server",
    "log_level": "INFO"
}


def clean_config(config: dict, config_type: str = "client") -> dict:
    """Clean and validate configuration.
    
    Removes invalid parameters, adds missing defaults, and validates required fields.
    
    Args:
        config: Raw configuration dictionary.
        config_type: 'server' or 'client'.
        
    Returns:
        Cleaned configuration dictionary.
    """
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
    """Save configuration to JSON file.
    
    Args:
        config_path: Path to config file.
        config: Configuration dictionary.
    """
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)


def load_and_clean_config(config_path: str, config_type: str = "client") -> dict:
    """Load config, clean it, save back if changed, return cleaned version.
    
    Args:
        config_path: Path to config file.
        config_type: 'server' or 'client'.
        
    Returns:
        Cleaned configuration dictionary.
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
    """Interactive wizard to generate server configuration.
    
    Args:
        config_path: Path to save config file.
        
    Returns:
        True if config was saved, False if cancelled.
    """
    if os.path.exists(config_path):
        overwrite = input(f"Config {config_path} already exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            return False
    
    config = {}
    
    print("\n=== Server Configuration Wizard ===\n")
    
    print("--- Encryption ---")
    print("Enter a pre-shared key (or press Enter for random generated):")
    psk = input("PSK Key: ").strip()
    if not psk:
        psk = secrets.token_hex(16)
        print(f"Generated random PSK: {psk}")
    config["encryption_key"] = psk
    
    print("\n--- Network ---")
    listen_addr = input("Listen address [0.0.0.0:8080]: ").strip()
    config["listen"] = listen_addr if listen_addr else "0.0.0.0:8080"
    
    print("\n--- Performance (press Enter for defaults) ---")
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    _prompt_float(config, "tcp_timeout", "TCP session timeout in seconds", 60)
    _prompt_float(config, "udp_timeout", "UDP session timeout in seconds", 120)
    _prompt_float(config, "cleanup_interval", "Session cleanup interval in seconds", 30)
    
    compress = input("Enable compression? (Y/n) [Y]: ").strip().lower()
    config["compression"] = compress != 'n'
    
    print("\n--- Logging ---")
    log_level = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    config["log_level"] = log_level if log_level in ["DEBUG", "INFO", "WARNING", "ERROR"] else "INFO"
    
    config = clean_config(config, "server")
    save_config(config_path, config)
    
    print(f"\nServer configuration saved to {config_path}")
    return True


def generate_client_config(config_path: str = "client_config.json") -> bool:
    """Interactive wizard to generate client configuration.
    
    Args:
        config_path: Path to save config file.
        
    Returns:
        True if config was saved, False if cancelled.
    """
    if os.path.exists(config_path):
        overwrite = input(f"Config {config_path} already exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            return False
    
    config = {}
    
    print("\n=== Client Configuration Wizard ===\n")
    
    print("--- Encryption ---")
    print("Enter a pre-shared key (or press Enter for random generated):")
    psk = input("PSK Key: ").strip()
    if not psk:
        psk = secrets.token_hex(16)
        print(f"Generated random PSK: {psk}")
    config["encryption_key"] = psk
    
    print("\n--- SOCKS5 Proxy ---")
    socks_addr = input("SOCKS5 listen address [127.0.0.1:1080]: ").strip()
    config["socks_listen"] = socks_addr if socks_addr else "127.0.0.1:1080"
    
    print("\n--- Server Connection ---")
    server_url = input("Server URL [http://localhost:8080/tunnel]: ").strip()
    config["server_url"] = server_url if server_url else "http://localhost:8080/tunnel"
    
    outbound_proxy = input("Outbound HTTP proxy (leave empty for none): ").strip()
    config["outbound_http_proxy"] = outbound_proxy if outbound_proxy else ""
    
    print("\n--- DNS Configuration ---")
    dns_mode = input("DNS resolution mode (local/server) [server]: ").strip().lower()
    config["dns_mode"] = dns_mode if dns_mode in ["local", "server"] else "server"
    
    print("\n--- Performance (press Enter for defaults) ---")
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    _prompt_float(config, "http_timeout", "HTTP request timeout in seconds", 30)
    _prompt_float(config, "heartbeat_interval", "Heartbeat interval in seconds", 1)
    _prompt_float(config, "batch_wait", "Batch wait time in seconds", 0.01)
    _prompt_float(config, "reconnect_delay", "Reconnect delay in seconds", 0.5)
    
    compress = input("Enable compression? (Y/n) [Y]: ").strip().lower()
    config["compression"] = compress != 'n'
    
    print("\n--- Bypass ---")
    bypass_local = input("Bypass localhost requests? (Y/n) [Y]: ").strip().lower()
    config["bypass_local"] = bypass_local != 'n'
    
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
