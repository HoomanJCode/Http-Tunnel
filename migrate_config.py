#!/usr/bin/env python3
"""
Convert old JSON config files to .env format.

Usage:
    python3 migrate_config.py server_config.json    # Creates/updates .env with server settings
    python3 migrate_config.py client_config.json    # Creates/updates .env with client settings
    python3 migrate_config.py --both                # Reads both and merges into .env
"""

import json
import sys
import os
from pathlib import Path

# Mapping: JSON key -> .env key
SERVER_MAP = {
    "encryption_key": "ENCRYPTION_KEY",
    "listen": None,  # Special: split into LISTEN_HOST and LISTEN_PORT
    "max_post_bytes": "MAX_POST_BYTES",
    "tcp_timeout": "TCP_TIMEOUT",
    "udp_timeout": "UDP_TIMEOUT",
    "connect_timeout": "CONNECT_TIMEOUT",
    "cleanup_interval": "CLEANUP_INTERVAL",
    "recv_buffer": "RECV_BUFFER",
    "send_buffer": "SEND_BUFFER",
    "read_chunk": "READ_CHUNK",
    "read_timeout": "READ_TIMEOUT",
    "read_extend": "READ_EXTEND",
    "udp_read_timeout": "UDP_READ_TIMEOUT",
    "compression": None,  # Not used in .env
    "log_level": "LOG_LEVEL",
}

CLIENT_MAP = {
    "encryption_key": "ENCRYPTION_KEY",
    "socks_listen": None,  # Special: split into SOCKS_LISTEN_HOST and SOCKS_LISTEN_PORT
    "server_url": "SERVER_URL",
    "outbound_http_proxy": "OUTBOUND_PROXY",
    "dns_mode": "DNS_MODE",
    "http_timeout": "HTTP_TIMEOUT",
    "connect_timeout": "CONNECT_TIMEOUT",
    "heartbeat_interval": "HEARTBEAT_INTERVAL",
    "heartbeat_max": "HEARTBEAT_MAX",
    "batch_wait": "BATCH_WAIT",
    "reconnect_delay": "RECONNECT_DELAY",
    "max_post_bytes": "MAX_POST_BYTES",
    "route_tls": "ROUTE_TLS",
    "route_http": "ROUTE_HTTP",
    "route_other": "ROUTE_OTHER",
    "recv_chunk": "RECV_CHUNK",
    "fast_drain_threshold": "FAST_DRAIN_THRESHOLD",
    "fast_drain_interval": "FAST_DRAIN_INTERVAL",
    "http_pool_size": "HTTP_POOL_SIZE",
    "bypass_local": "BYPASS_LOCAL",
    "bypass_ranges": "BYPASS_RANGES",
    "high_priority_ports": "HIGH_PRIORITY_PORTS",
    "compression": None,
    "compress_threshold": None,
    "skip_compress_tls": None,
    "log_level": "LOG_LEVEL",
}


def convert_server(json_config: dict) -> dict:
    """Convert server JSON config to .env values."""
    env = {}
    for json_key, env_key in SERVER_MAP.items():
        if env_key is None:
            continue
        if json_key in json_config:
            val = json_config[json_key]
            if isinstance(val, bool):
                val = str(val).lower()
            elif isinstance(val, list):
                val = ",".join(str(v) for v in val)
            env[env_key] = str(val)
    
    # Split listen into host and port
    if "listen" in json_config:
        listen = json_config["listen"]
        if ":" in listen:
            host, port = listen.rsplit(":", 1)
            env["LISTEN_HOST"] = host
            env["LISTEN_PORT"] = port
    
    return env


def convert_client(json_config: dict) -> dict:
    """Convert client JSON config to .env values."""
    env = {}
    for json_key, env_key in CLIENT_MAP.items():
        if env_key is None:
            continue
        if json_key in json_config:
            val = json_config[json_key]
            if isinstance(val, bool):
                val = str(val).lower()
            elif isinstance(val, list):
                val = ",".join(str(v) for v in val)
            env[env_key] = str(val)
    
    # Split socks_listen into host and port
    if "socks_listen" in json_config:
        listen = json_config["socks_listen"]
        if ":" in listen:
            host, port = listen.rsplit(":", 1)
            env["SOCKS_LISTEN_HOST"] = host
            env["SOCKS_LISTEN_PORT"] = port
    
    return env


def write_env(env_values: dict, path: str = ".env"):
    """Write or update .env file with new values."""
    env_file = Path(path)
    existing = {}
    
    # Read existing .env if present
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    existing[k.strip()] = v.strip()
    
    # Merge new values (new override existing)
    existing.update(env_values)
    
    # Write back
    with open(env_file, 'w') as f:
        f.write("# HTTP Tunnel Configuration\n")
        f.write("# Generated from JSON config migration\n\n")
        for key in sorted(existing.keys()):
            f.write(f"{key}={existing[key]}\n")
    
    print(f"✅ Written {len(env_values)} values to {env_file}")
    if env_file.absolute() != Path(path).absolute():
        print(f"   Full path: {env_file.absolute()}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 migrate_config.py server_config.json")
        print("  python3 migrate_config.py client_config.json")
        print("  python3 migrate_config.py --both")
        sys.exit(1)
    
    arg = sys.argv[1]
    env_values = {}
    
    if arg == "--both":
        if os.path.exists("server_config.json"):
            with open("server_config.json") as f:
                env_values.update(convert_server(json.load(f)))
            print(f"📄 Read server_config.json")
        if os.path.exists("client_config.json"):
            with open("client_config.json") as f:
                env_values.update(convert_client(json.load(f)))
            print(f"📄 Read client_config.json")
    elif arg.endswith("server_config.json"):
        if not os.path.exists(arg):
            print(f"❌ File not found: {arg}")
            sys.exit(1)
        with open(arg) as f:
            env_values = convert_server(json.load(f))
        print(f"📄 Read {arg}")
    elif arg.endswith("client_config.json"):
        if not os.path.exists(arg):
            print(f"❌ File not found: {arg}")
            sys.exit(1)
        with open(arg) as f:
            env_values = convert_client(json.load(f))
        print(f"📄 Read {arg}")
    else:
        print(f"❌ Unknown argument: {arg}")
        print("   Use server_config.json, client_config.json, or --both")
        sys.exit(1)
    
    if not env_values:
        print("❌ No values to migrate")
        sys.exit(1)
    
    write_env(env_values)


if __name__ == "__main__":
    main()