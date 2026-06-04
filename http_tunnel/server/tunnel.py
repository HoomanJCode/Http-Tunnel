"""Server entry point."""

import os
import socket
from http.server import HTTPServer
from socketserver import ThreadingMixIn

from http_tunnel.config import SERVER_CONFIG
from http_tunnel.logging import setup_logging
from http_tunnel.crypto import TunnelCrypto
from http_tunnel.server.handler import TunnelRequestHandler
from http_tunnel.server.cleaner import SessionCleaner


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTP server that handles each request in a separate thread."""
    daemon_threads = True
    request_queue_size = 128


def run_server():
    config = SERVER_CONFIG
    
    if not config.get('encryption_key'):
        print("❌ ENCRYPTION_KEY not set in .env file")
        print("   Create .env with: ENCRYPTION_KEY=your-secret-key")
        return
    
    logger = setup_logging(config, "server")
    logger.info("Starting server...")
    
    TunnelRequestHandler.logger = logger
    TunnelRequestHandler.crypto = TunnelCrypto(config['encryption_key'])
    TunnelRequestHandler.max_post_bytes = int(config['max_post_bytes'])
    TunnelRequestHandler.tcp_timeout = float(config['tcp_timeout'])
    TunnelRequestHandler.udp_timeout = float(config['udp_timeout'])
    TunnelRequestHandler.connect_timeout = float(config['connect_timeout'])
    TunnelRequestHandler.recv_buffer = int(config['recv_buffer'])
    TunnelRequestHandler.send_buffer = int(config['send_buffer'])
    TunnelRequestHandler.read_chunk = int(config['read_chunk'])
    TunnelRequestHandler.read_timeout = float(config['read_timeout'])
    TunnelRequestHandler.read_extend = float(config['read_extend'])
    TunnelRequestHandler.udp_read_timeout = float(config['udp_read_timeout'])
    
    cleaner = SessionCleaner(TunnelRequestHandler, float(config['cleanup_interval']))
    cleaner.start()
    
    host = config['listen_host']
    port = int(config['listen_port'])
    server = ThreadingHTTPServer((host, port), TunnelRequestHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    logger.info(f"Listening on {host}:{port} (multi-threaded)")
    logger.info(f"TCP timeout: {config['tcp_timeout']}s, UDP: {config['udp_timeout']}s")
    logger.info(f"Buffers: recv={config['recv_buffer']}, send={config['send_buffer']}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()