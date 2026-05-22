#!/usr/bin/env python3
"""HTTP Tunnel Client - Entry point."""

import sys
import os

# Add project root to Python path so http_tunnel package can be found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from http_tunnel.client.tunnel import SocksToHttpTunnel

if __name__ == "__main__":
    tunnel = SocksToHttpTunnel()
    tunnel.start()