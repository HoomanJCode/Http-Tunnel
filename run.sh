#!/bin/bash

cd "$(dirname "$0")"

# Create venv if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install dependencies if needed
if ! pip show cryptography &>/dev/null || ! pip show requests &>/dev/null; then
    echo "Installing dependencies..."
    pip install -q -r requirements.txt
fi

# Run based on argument
if [ "$1" == "client" ]; then
    echo "Starting tunnel client..."
    python3 client.py
elif [ "$1" == "server" ]; then
    echo "Starting tunnel server..."
    python3 server.py
else
    echo "HTTP Tunnel - TCP/UDP over HTTP POST"
    echo ""
    echo "Usage: ./run.sh [server|client]"
    echo "  server - Start the tunnel server"
    echo "  client - Start the tunnel client (SOCKS5 proxy)"
    echo ""
    echo "Examples:"
    echo "  ./run.sh server"
    echo "  ./run.sh client"
    echo ""
    echo "After starting client, use with curl:"
    echo "  curl --socks5-hostname 127.0.0.1:1080 --ipv4 https://example.com"
    exit 1
fi