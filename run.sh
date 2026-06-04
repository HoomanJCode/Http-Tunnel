#!/bin/bash
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

if [ "$1" == "client" ]; then
    echo "Starting client..."
    python3 client.py
elif [ "$1" == "server" ]; then
    echo "Starting server..."
    python3 server.py
else
    echo "Usage: ./run.sh [server|client]"
fi