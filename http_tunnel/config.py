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
    "log_level": "INFO"
}

CLIENT_CONFIG_PARAMS = {
    "encryption_key": _REQUIRED,
    "socks_listen": _REQUIRED,
    "server_url": _REQUIRED,
    "outbound_http_proxy": "",
    "dns_mode": "server",
    "http_timeout": 45,
    "connect_timeout": 8,
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
    print("\nTimeouts (Enter for defaults):")
    _prompt_float(config, "connect_timeout", "TCP connect timeout (s)", 8)
    _prompt_float(config, "tcp_timeout", "TCP idle timeout (s)", 60)
    _prompt_float(config, "udp_timeout", "UDP idle timeout (s)", 120)
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    _prompt_float(config, "cleanup_interval", "Cleanup interval (s)", 30)
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
    print("\nSOCKS5:")
    config["socks_listen"] = input("Listen address [127.0.0.1:1080]: ").strip() or "127.0.0.1:1080"
    print("\nServer:")
    config["server_url"] = input("Server URL [http://localhost:8080/tunnel]: ").strip() or "http://localhost:8080/tunnel"
    config["outbound_http_proxy"] = input("Outbound proxy (empty=none): ").strip()
    print("\nDNS (server=no leaks):")
    config["dns_mode"] = input("DNS mode (local/server) [server]: ").strip().lower() or "server"
    print("\nTimeouts (Enter for defaults):")
    _prompt_float(config, "connect_timeout", "TCP connect timeout (s)", 8)
    _prompt_float(config, "http_timeout", "HTTP timeout (s)", 45)
    _prompt_float(config, "heartbeat_interval", "Heartbeat (s)", 1)
    _prompt_float(config, "batch_wait", "Batch wait (s, 0=instant)", 0.01)
    _prompt_float(config, "reconnect_delay", "Reconnect delay (s)", 0.5)
    _prompt_int(config, "max_post_bytes", "Max POST bytes", 5242880)
    print("\nBypass:")
    config["bypass_local"] = input("Bypass localhost? (Y/n) [Y]: ").strip().lower() != 'n'
    bypass_input = input("Bypass CIDRs (comma, Enter=defaults): ").strip()
    config["bypass_ranges"] = [r.strip() for r in bypass_input.split(",")] if bypass_input else ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    print("\nQoS (lower batch wait for these ports):")
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