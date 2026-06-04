#!/usr/bin/env python3
"""
Deploy HTTP Tunnel Server to VPS via SSH.
Reads .env from current directory and deploys to remote server.

Usage:
    python3 deploy.py                      # Deploy with .env values
    python3 deploy.py --dry-run            # Show what would happen
    python3 deploy.py --restart            # Only restart service
    python3 deploy.py --status             # Check service status
"""

import os
import sys
import argparse
import subprocess
import tempfile
from pathlib import Path

# ─── Configuration ──────────────────────────────────────
VPS_HOST = os.getenv("VPS_HOST", "")
VPS_USER = os.getenv("VPS_USER", "root")
VPS_PORT = os.getenv("VPS_PORT", "22")
PROJECT_DIR = "/opt/http-tunnel"
SERVICE_NAME = "http-tunnel-server"
REPO_URL = "https://github.com/HoomanJCode/Http-Tunnel.git"

# Read .env if exists
def load_env():
    env_file = Path(".env")
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    val = val.strip().strip('"').strip("'")
                    if key and val:
                        os.environ[key] = val


# ─── Script generation ──────────────────────────────────
def generate_deploy_script():
    """Generate the bash deployment script."""
    encryption_key = os.getenv("ENCRYPTION_KEY", "")
    listen_port = os.getenv("LISTEN_PORT", "8080")
    log_level = os.getenv("LOG_LEVEL", "INFO")
    
    if not encryption_key:
        print("⚠️  ENCRYPTION_KEY not set in .env, server will generate random key")
    
    script = f'''#!/bin/bash
set -e

PROJECT_DIR="{PROJECT_DIR}"
SERVICE_NAME="{SERVICE_NAME}"

echo "========================================"
echo "  HTTP Tunnel Server Deployment"
echo "========================================"

# Install dependencies
echo "📦 Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git curl

# Stop existing service
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "⏹️  Stopping $SERVICE_NAME..."
    systemctl stop $SERVICE_NAME
    sleep 2
fi

# Deploy code
if [ -d "$PROJECT_DIR/.git" ]; then
    echo "📥 Pulling latest code..."
    cd "$PROJECT_DIR"
    git fetch origin
    git reset --hard origin/master
    git clean -fd -e ".env" -e "*.log"
else
    echo "📥 Cloning repository..."
    rm -rf "$PROJECT_DIR"
    git clone --depth 1 {REPO_URL} "$PROJECT_DIR"
    cd "$PROJECT_DIR"
fi

# Create .env
echo "⚙️  Creating .env..."
cat > "$PROJECT_DIR/.env" << ENVEOF
ENCRYPTION_KEY={encryption_key}
LISTEN_HOST=0.0.0.0
LISTEN_PORT={listen_port}
LOG_LEVEL={log_level}
ENVEOF
chmod 600 "$PROJECT_DIR/.env"

# Setup Python venv
echo "🐍 Setting up Python..."
cd "$PROJECT_DIR"
[ -d venv ] && rm -rf venv
python3 -m venv venv
$PROJECT_DIR/venv/bin/pip install --upgrade pip -q
$PROJECT_DIR/venv/bin/pip install -r requirements.txt -q

# Validate
echo "🧪 Testing imports..."
$PROJECT_DIR/venv/bin/python -c "
import sys; sys.path.insert(0, '$PROJECT_DIR')
from http_tunnel.server.tunnel import run_server
print('✅ Server module loaded successfully')
"

# Create systemd service
echo "🔧 Creating systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME.service << SERVICEEOF
[Unit]
Description=HTTP Tunnel Server - TCP/UDP over HTTP POST
After=network.target
Documentation={REPO_URL}

[Service]
Type=simple
User=nobody
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$PROJECT_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin
Environment=PYTHONUNBUFFERED=1
ExecStart=$PROJECT_DIR/venv/bin/python $PROJECT_DIR/server.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/$SERVICE_NAME.log
StandardError=append:/var/log/$SERVICE_NAME.log

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$PROJECT_DIR
ReadOnlyPaths=/usr/bin /usr/lib /usr/lib64 /lib /lib64

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME

# Start service
echo "▶️  Starting service..."
systemctl start $SERVICE_NAME
sleep 3

if systemctl is-active --quiet $SERVICE_NAME; then
    echo "✅ Service is running!"
    systemctl status $SERVICE_NAME --no-pager -l
    
    echo ""
    echo "📊 Recent logs:"
    tail -10 /var/log/$SERVICE_NAME.log 2>/dev/null || echo "  (no logs yet)"
else
    echo "❌ Service failed to start!"
    echo ""
    echo "=== Error Log ==="
    tail -20 /var/log/$SERVICE_NAME.log 2>/dev/null || echo "No log found"
    echo ""
    echo "=== Journal ==="
    journalctl -u $SERVICE_NAME -n 20 --no-pager || true
    exit 1
fi

echo ""
echo "✅ Deployment Complete!"
echo "📊 Monitor: tail -f /var/log/$SERVICE_NAME.log"
echo "📋 Status: systemctl status $SERVICE_NAME"
echo "🔄 Restart: systemctl restart $SERVICE_NAME"
echo "⏹️  Stop: systemctl stop $SERVICE_NAME"
'''
    return script


# ─── SSH helpers ────────────────────────────────────────
def ssh_cmd(host, user, port, command):
    """Run command on remote server."""
    return [
        "ssh", "-o", "StrictHostKeyChecking=accept-new",
        "-p", port, f"{user}@{host}", command
    ]


def scp_cmd(host, user, port, local_file, remote_file):
    """Copy file to remote server."""
    return [
        "scp", "-o", "StrictHostKeyChecking=accept-new",
        "-P", port, local_file, f"{user}@{host}:{remote_file}"
    ]


def run(cmd, dry_run=False):
    """Run command locally or print it."""
    if dry_run:
        print(f"  [DRY RUN] {' '.join(cmd)}")
        return True
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ❌ Error: {result.stderr}")
        return False
    if result.stdout:
        print(result.stdout)
    return True


# ─── Commands ───────────────────────────────────────────
def deploy(dry_run=False):
    """Full deployment."""
    if not VPS_HOST:
        print("❌ VPS_HOST not set. Export it or add to .env:")
        print("   export VPS_HOST=your-server.com")
        sys.exit(1)
    
    print(f"🚀 Deploying to {VPS_USER}@{VPS_HOST}:{VPS_PORT}")
    print(f"   Project: {PROJECT_DIR}")
    print()
    
    # Generate script
    script = generate_deploy_script()
    
    if dry_run:
        print("=" * 50)
        print("  DEPLOY SCRIPT (dry run)")
        print("=" * 50)
        print(script)
        return
    
    # Write script to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
        f.write(script)
        script_path = f.name
    
    try:
        # Upload script
        print("📤 Uploading deploy script...")
        if not run(scp_cmd(VPS_HOST, VPS_USER, VPS_PORT, script_path, "/tmp/deploy.sh")):
            sys.exit(1)
        
        # Run script
        print("🖥️  Executing deploy script...")
        if not run(ssh_cmd(VPS_HOST, VPS_USER, VPS_PORT, "bash /tmp/deploy.sh")):
            sys.exit(1)
        
        print("\n✅ Deployment successful!")
    finally:
        os.unlink(script_path)


def restart_service(dry_run=False):
    """Restart the service."""
    print(f"🔄 Restarting {SERVICE_NAME} on {VPS_HOST}...")
    if not run(ssh_cmd(VPS_HOST, VPS_USER, VPS_PORT, f"systemctl restart {SERVICE_NAME}"), dry_run):
        sys.exit(1)
    if not dry_run:
        run(ssh_cmd(VPS_HOST, VPS_USER, VPS_PORT, f"systemctl status {SERVICE_NAME} --no-pager -l"))


def check_status(dry_run=False):
    """Check service status."""
    print(f"📋 Status of {SERVICE_NAME} on {VPS_HOST}:")
    run(ssh_cmd(VPS_HOST, VPS_USER, VPS_PORT, f"systemctl status {SERVICE_NAME} --no-pager -l"), dry_run)
    print()
    print("📊 Recent logs:")
    run(ssh_cmd(VPS_HOST, VPS_USER, VPS_PORT, f"tail -30 /var/log/{SERVICE_NAME}.log"), dry_run)


def show_logs(dry_run=False):
    """Show recent logs."""
    run(ssh_cmd(VPS_HOST, VPS_USER, VPS_PORT, f"tail -50 /var/log/{SERVICE_NAME}.log"), dry_run)


# ─── Main ───────────────────────────────────────────────
def main():
    load_env()
    
    parser = argparse.ArgumentParser(description="HTTP Tunnel Server Deployment")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without doing it")
    parser.add_argument("--restart", action="store_true", help="Restart the service")
    parser.add_argument("--status", action="store_true", help="Check service status")
    parser.add_argument("--logs", action="store_true", help="Show recent logs")
    
    args = parser.parse_args()
    
    if args.restart:
        restart_service(args.dry_run)
    elif args.status:
        check_status(args.dry_run)
    elif args.logs:
        show_logs(args.dry_run)
    else:
        deploy(args.dry_run)


if __name__ == "__main__":
    main()