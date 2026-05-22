"""Server entry point."""

import json
import os
import socket
from http.server import HTTPServer

from http_tunnel.config import generate_server_config, load_and_clean_config
from http_tunnel.logging import setup_logging
from http_tunnel.crypto import TunnelCrypto
from http_tunnel.server.handler import TunnelRequestHandler
from http_tunnel.server.cleaner import SessionCleaner


def run_server():
    """Initialize and run the tunnel server."""
    config_path = "server_config.json"
    
    if not os.path.exists(config_path):
        print(f"Config file {config_path} not found. Running setup wizard...")
        if not generate_server_config(config_path):
            print("Setup cancelled.")
            return
    
    config = load_and_clean_config(config_path, "server")
    logger = setup_logging(config, "server")
    logger.info("Loading server configuration...")
    
    # Configure handler
    TunnelRequestHandler.logger = logger
    TunnelRequestHandler.crypto = TunnelCrypto(config["encryption_key"])
    TunnelRequestHandler.max_post_bytes = config["max_post_bytes"]
    TunnelRequestHandler.tcp_timeout = config["tcp_timeout"]
    TunnelRequestHandler.udp_timeout = config["udp_timeout"]
    TunnelRequestHandler.compression = config["compression"]
    
    # Start session cleaner
    cleaner = SessionCleaner(TunnelRequestHandler, config["cleanup_interval"])
    cleaner.start()
    
    # Start HTTP server
    host, port = config["listen"].split(":")
    server = HTTPServer((host, int(port)), TunnelRequestHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    logger.info(f"Listening on {host}:{port}")
    logger.info(f"TCP timeout: {config['tcp_timeout']}s, "
                f"UDP timeout: {config['udp_timeout']}s")
    logger.info(f"Compression: {'ON' if config['compression'] else 'OFF'}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()
