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
    "cleanup_interval": 30,
    "log_level": "INFO"
}

CLIENT_CONFIG_PARAMS = {
    "encryption_key": _REQUIRED,
    "socks_listen": _REQUIRED,
    "server_url": _REQUIRED,
    "outbound_http_proxy": "",
    "dns_mode": "server",
    "http_timeout": 45,
    "heartbeat_interval": 1,
    "batch_wait": 0.01,
    "reconnect_delay": 0.5,
    "max_post_bytes": 5242880,
    "bypass_local": True,
    "bypass_ranges": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "high_priority_ports": [22, 80, 443, 8080],
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
        overwrite = input(f"Config {config_path} exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
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
    listen_addr = input("Listen address [0.0.0.0:8080]: ").strip()
    config["listen"] = listen_addr if listen_addr else "0.0.0.0:8080"
    print("\nPerformance (Enter for defaults):")
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    _prompt_float(config, "tcp_timeout", "TCP timeout (s)", 60)
    _prompt_float(config, "udp_timeout", "UDP timeout (s)", 120)
    _prompt_float(config, "cleanup_interval", "Cleanup interval (s)", 30)
    print("\nLogging:")
    log_level = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    config["log_level"] = log_level if log_level in ["DEBUG", "INFO", "WARNING", "ERROR"] else "INFO"
    config = clean_config(config, "server")
    save_config(config_path, config)
    print(f"\nSaved: {config_path}")
    return True


def generate_client_config(config_path: str = "client_config.json") -> bool:
    if os.path.exists(config_path):
        overwrite = input(f"Config {config_path} exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            return False
    config = {}
    print("\n=== Client Configuration ===\n")
    print("Encryption Key (Enter for random):")
    psk = input("PSK Key: ").strip()
    if not psk:
        psk = secrets.token_hex(16)
        print(f"Generated: {psk}")
    config["encryption_key"] = psk
    print("\nSOCKS5 Proxy:")
    socks_addr = input("Listen address [127.0.0.1:1080]: ").strip()
    config["socks_listen"] = socks_addr if socks_addr else "127.0.0.1:1080"
    print("\nServer:")
    server_url = input("Server URL [http://localhost:8080/tunnel]: ").strip()
    config["server_url"] = server_url if server_url else "http://localhost:8080/tunnel"
    outbound_proxy = input("Outbound proxy (empty=none): ").strip()
    config["outbound_http_proxy"] = outbound_proxy if outbound_proxy else ""
    print("\nDNS (server=no leaks):")
    dns_mode = input("DNS mode (local/server) [server]: ").strip().lower()
    config["dns_mode"] = dns_mode if dns_mode in ["local", "server"] else "server"
    print("\nTiming (Enter for defaults):")
    _prompt_float(config, "http_timeout", "HTTP timeout (s)", 45)
    _prompt_float(config, "heartbeat_interval", "Heartbeat (s)", 1)
    _prompt_float(config, "batch_wait", "Batch wait (s, 0=instant)", 0.01)
    _prompt_float(config, "reconnect_delay", "Reconnect delay (s)", 0.5)
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    print("\nBypass:")
    bypass_local = input("Bypass localhost? (Y/n) [Y]: ").strip().lower()
    config["bypass_local"] = bypass_local != 'n'
    bypass_input = input("Bypass CIDRs (comma, Enter=defaults): ").strip()
    if bypass_input:
        config["bypass_ranges"] = [r.strip() for r in bypass_input.split(",")]
    else:
        config["bypass_ranges"] = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    print("\nQoS (lower batch wait for these ports):")
    qos_input = input("Priority ports (comma, Enter=defaults): ").strip()
    if qos_input:
        config["high_priority_ports"] = [int(p.strip()) for p in qos_input.split(",")]
    else:
        config["high_priority_ports"] = [22, 80, 443, 8080]
    print("\nLogging:")
    log_level = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    config["log_level"] = log_level if log_level in ["DEBUG", "INFO", "WARNING", "ERROR"] else "INFO"
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