#!/usr/bin/env python3
"""HTTP Tunnel Client - Entry point."""

from http_tunnel.client import SocksToHttpTunnel

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()
