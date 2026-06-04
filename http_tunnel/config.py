"""Configuration via .env file and environment variables."""

import os
import secrets
from dotenv import load_dotenv

# MUST be first - load .env before reading any values
load_dotenv()


def _env(key, default=None, cast=str):
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return cast(val)
    except (ValueError, TypeError):
        return default


# ─── Server Config ──────────────────────────────────────
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

# ─── Client Config ──────────────────────────────────────
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