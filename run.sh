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
    echo "Starting client..."
    python3 client.py
elif [ "$1" == "server" ]; then
    echo "Starting server..."
    python3 server.py
else
    echo "Usage: ./run.sh [server|client]"
    echo "  server - Start the tunnel server"
    echo "  client - Start the tunnel client"
    exit 1
fi