#!/usr/bin/env python3
"""
Zero-touch VPS deployment for HTTP Tunnel Server.
Connects via SSH, installs everything, sets up service.

Prerequisites:
    pip install python-dotenv

Usage:
    python3 deploy.py                    # Deploy with .env values
    python3 deploy.py --dry-run          # Preview without executing
    python3 deploy.py --restart          # Only restart service
    python3 deploy.py --status           # Check service status
    python3 deploy.py --logs             # View recent logs
    python3 deploy.py --uninstall        # Remove everything

Required .env variables:
    VPS_HOST=your-server.com
    VPS_USER=root
    VPS_PORT=22
    ENCRYPTION_KEY=your-secret-key

Optional .env variables (defaults used if not set):
    LISTEN_PORT=8080
    LOG_LEVEL=INFO
"""

import os
import sys
import argparse
import subprocess
import tempfile
import textwrap
from pathlib import Path

# ─── Load .env ──────────────────────────────────────────
def load_env():
    """Load .env file from current directory."""
    env_file = Path(".env")
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            # Fallback: manual parsing
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, val = line.partition("=")
                        val = val.strip().strip('"').strip("'")
                        if key and val:
                            os.environ[key] = val


# ─── Configuration ──────────────────────────────────────
load_env()

VPS_HOST = os.getenv("VPS_HOST", "")
VPS_USER = os.getenv("VPS_USER", "root")
VPS_PORT = os.getenv("VPS_PORT", "22")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
LISTEN_PORT = os.getenv("LISTEN_PORT", "8080")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

PROJECT_DIR = "/opt/http-tunnel"
SERVICE_NAME = "http-tunnel-server"
REPO_URL = "https://github.com/HoomanJCode/Http-Tunnel.git"


# ─── Deploy Script Generation ───────────────────────────
def generate_deploy_script():
    """Generate complete bash script that sets up everything on VPS."""
    
    script = textwrap.dedent(f'''\
    #!/bin/bash
    set -e

    PROJECT_DIR="{PROJECT_DIR}"
    SERVICE_NAME="{SERVICE_NAME}"
    REPO_URL="{REPO_URL}"

    echo "=========================================="
    echo "  HTTP Tunnel Server - Auto Deploy"
    echo "=========================================="
    echo "  Server: $(hostname)"
    echo "  Time:   $(date)"
    echo "=========================================="
    echo ""

    # ─── System Setup ──────────────────────────────────
    echo "[1/7] 📦 Updating system and installing packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv git curl ufw 2>&1 | tail -1

    # ─── Firewall ──────────────────────────────────────
    echo "[2/7] 🔥 Configuring firewall..."
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming > /dev/null
    ufw default allow outgoing > /dev/null
    ufw allow ssh > /dev/null
    ufw allow {LISTEN_PORT}/tcp comment "HTTP Tunnel Server" > /dev/null
    ufw --force enable > /dev/null
    echo "  ✅ Firewall configured (SSH + {LISTEN_PORT})"

    # ─── Create User ───────────────────────────────────
    echo "[3/7] 👤 Creating service user..."
    if ! id -u tunnel > /dev/null 2>&1; then
        useradd -r -s /usr/sbin/nologin -d /nonexistent -M tunnel
        echo "  ✅ User 'tunnel' created"
    else
        echo "  ✅ User 'tunnel' already exists"
    fi

    # ─── Clone Repository ──────────────────────────────
    echo "[4/7] 📥 Deploying code..."
    if [ -d "$PROJECT_DIR/.git" ]; then
        cd "$PROJECT_DIR"
        git fetch origin --quiet
        git reset --hard origin/master --quiet
        git clean -fd -e ".env" -e "*.log" --quiet
        echo "  ✅ Code updated"
    else
        mkdir -p "$PROJECT_DIR"
        git clone --depth 1 "$REPO_URL" "$PROJECT_DIR" --quiet
        echo "  ✅ Code cloned"
    fi

    # ─── Create .env ───────────────────────────────────
    echo "[5/7] ⚙️  Creating configuration..."
    cat > "$PROJECT_DIR/.env" << 'ENVEOF'
    ENCRYPTION_KEY={ENCRYPTION_KEY}
    LISTEN_HOST=0.0.0.0
    LISTEN_PORT={LISTEN_PORT}
    LOG_LEVEL={LOG_LEVEL}
    ENVEOF
    chmod 600 "$PROJECT_DIR/.env"
    chown -R tunnel:tunnel "$PROJECT_DIR"
    echo "  ✅ .env created"

    # ─── Python Environment ────────────────────────────
    echo "[6/7] 🐍 Setting up Python..."
    cd "$PROJECT_DIR"
    if [ -d venv ]; then
        rm -rf venv
    fi
    python3 -m venv venv
    "$PROJECT_DIR/venv/bin/pip" install --upgrade pip -q 2>&1 | tail -1
    "$PROJECT_DIR/venv/bin/pip" install -r requirements.txt -q 2>&1 | tail -1

    # Verify imports work
    "$PROJECT_DIR/venv/bin/python" -c "
    import sys; sys.path.insert(0, '$PROJECT_DIR')
    from http_tunnel.server.tunnel import run_server
    from http_tunnel.crypto import TunnelCrypto
    print('  ✅ All modules loaded')
    "

    # ─── Systemd Service ───────────────────────────────
    echo "[7/7] 🔧 Creating systemd service..."
    cat > /etc/systemd/system/$SERVICE_NAME.service << 'SERVICEEOF'
    [Unit]
    Description=HTTP Tunnel Server - TCP/UDP over HTTP
    After=network.target
    Documentation={REPO_URL}

    [Service]
    Type=simple
    User=tunnel
    WorkingDirectory={PROJECT_DIR}
    Environment=PATH={PROJECT_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin
    Environment=PYTHONUNBUFFERED=1
    ExecStart={PROJECT_DIR}/venv/bin/python {PROJECT_DIR}/server.py
    Restart=always
    RestartSec=5
    StandardOutput=append:/var/log/{SERVICE_NAME}.log
    StandardError=append:/var/log/{SERVICE_NAME}.log

    # Security
    NoNewPrivileges=yes
    PrivateTmp=yes
    ProtectSystem=strict
    ProtectHome=yes
    ReadWritePaths={PROJECT_DIR}
    ReadOnlyPaths=/usr/bin /usr/lib /usr/lib64 /lib /lib64 /etc/ssl /etc/ca-certificates

    [Install]
    WantedBy=multi-user.target
    SERVICEEOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME --quiet

    # ─── Start Service ─────────────────────────────────
    echo ""
    echo "▶️  Starting service..."
    systemctl restart $SERVICE_NAME
    sleep 4

    if systemctl is-active --quiet $SERVICE_NAME; then
        echo ""
        echo "✅ SERVICE IS RUNNING!"
        echo ""
        systemctl status $SERVICE_NAME --no-pager -l
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  🌐 Tunnel Server Ready"
        echo "  📡 Listening: 0.0.0.0:{LISTEN_PORT}"
        echo "  🔑 Key: {ENCRYPTION_KEY[:12]}***"
        echo "  📋 Status: systemctl status {SERVICE_NAME}"
        echo "  📊 Logs:   tail -f /var/log/{SERVICE_NAME}.log"
        echo "  🔄 Restart: systemctl restart {SERVICE_NAME}"
        echo "  ⏹️  Stop:    systemctl stop {SERVICE_NAME}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "📊 Recent logs:"
        tail -10 /var/log/{SERVICE_NAME}.log 2>/dev/null || echo "  (logs will appear here)"
    else
        echo ""
        echo "❌ SERVICE FAILED TO START!"
        echo ""
        echo "─── Error Log ───"
        tail -30 /var/log/{SERVICE_NAME}.log 2>/dev/null || echo "No log"
        echo ""
        echo "─── Journal ───"
        journalctl -u $SERVICE_NAME -n 30 --no-pager || true
        exit 1
    fi

    echo ""
    echo "✅ Zero-touch deployment complete!"
    ''')
    
    return script


def generate_uninstall_script():
    """Generate bash script to completely remove the server."""
    return textwrap.dedent(f'''\
    #!/bin/bash
    set -e

    echo "🗑️  Removing HTTP Tunnel Server..."

    # Stop and disable service
    systemctl stop {SERVICE_NAME} 2>/dev/null || true
    systemctl disable {SERVICE_NAME} 2>/dev/null || true
    rm -f /etc/systemd/system/{SERVICE_NAME}.service
    systemctl daemon-reload

    # Remove files
    rm -rf {PROJECT_DIR}
    rm -f /var/log/{SERVICE_NAME}.log

    # Remove user
    userdel tunnel 2>/dev/null || true

    # Remove firewall rule
    ufw delete allow {LISTEN_PORT}/tcp 2>/dev/null || true

    echo "✅ HTTP Tunnel Server removed."
    echo "   Firewall: port {LISTEN_PORT} closed"
    echo "   Files: {PROJECT_DIR} deleted"
    echo "   Service: {SERVICE_NAME} removed"
    ''')


# ─── SSH Helpers ────────────────────────────────────────
def ssh_args():
    return [
        "ssh", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-p", VPS_PORT, f"{VPS_USER}@{VPS_HOST}"
    ]


def scp_args(local_file, remote_file):
    return [
        "scp", "-o", "StrictHostKeyChecking=accept-new",
        "-P", VPS_PORT, local_file, f"{VPS_USER}@{VPS_HOST}:{remote_file}"
    ]


def run_remote(cmd, dry_run=False):
    """Run command on VPS."""
    full_cmd = ssh_args() + [cmd]
    if dry_run:
        print(f"  [DRY RUN] {' '.join(full_cmd)}")
        return True, ""
    
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        print(output)
        return False, output
    return True, output


def upload_and_run(script_content, dry_run=False):
    """Upload script to VPS and execute it."""
    if dry_run:
        print("=" * 60)
        print("  DEPLOY SCRIPT (dry run)")
        print("=" * 60)
        print(script_content)
        return True
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
        f.write(script_content)
        script_path = f.name
    
    try:
        # Upload
        result = subprocess.run(
            scp_args(script_path, "/tmp/tunnel_deploy.sh"),
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"❌ Upload failed: {result.stderr}")
            return False
        
        # Execute
        success, output = run_remote("bash /tmp/tunnel_deploy.sh")
        if output:
            print(output)
        return success
    finally:
        os.unlink(script_path)


# ─── Commands ───────────────────────────────────────────
def cmd_deploy(dry_run=False):
    """Full zero-touch deployment."""
    if not VPS_HOST:
        print("❌ VPS_HOST not set.")
        print("   Add to .env: VPS_HOST=your-server.com")
        sys.exit(1)
    if not ENCRYPTION_KEY:
        print("❌ ENCRYPTION_KEY not set.")
        print("   Add to .env: ENCRYPTION_KEY=your-secret-key")
        print("   (use a long random string)")
        sys.exit(1)
    
    print(f"🚀 Deploying to {VPS_USER}@{VPS_HOST}:{VPS_PORT}")
    print(f"   Port: {LISTEN_PORT}")
    print(f"   Key:  {ENCRYPTION_KEY[:12]}***")
    print()
    
    script = generate_deploy_script()
    success = upload_and_run(script, dry_run)
    
    if success and not dry_run:
        print("\n✅ Deployment complete!")
        print(f"   Client config: SERVER_URL=http://{VPS_HOST}:{LISTEN_PORT}/tunnel")


def cmd_uninstall(dry_run=False):
    """Remove everything from VPS."""
    if not VPS_HOST:
        print("❌ VPS_HOST not set.")
        sys.exit(1)
    
    print(f"⚠️  This will COMPLETELY REMOVE the server from {VPS_HOST}")
    if not dry_run:
        confirm = input("Type 'yes' to confirm: ")
        if confirm != "yes":
            print("Cancelled.")
            return
    
    script = generate_uninstall_script()
    upload_and_run(script, dry_run)


def cmd_status(dry_run=False):
    """Check service status."""
    success, output = run_remote(f"systemctl status {SERVICE_NAME} --no-pager -l && echo '---' && tail -20 /var/log/{SERVICE_NAME}.log 2>/dev/null || echo 'No logs'")
    if output:
        print(output)


def cmd_logs(dry_run=False):
    """Show logs."""
    success, output = run_remote(f"tail -50 /var/log/{SERVICE_NAME}.log 2>/dev/null || echo 'No logs yet'")
    if output:
        print(output)


def cmd_restart(dry_run=False):
    """Restart service."""
    print(f"🔄 Restarting {SERVICE_NAME}...")
    success, output = run_remote(f"systemctl restart {SERVICE_NAME} && sleep 2 && systemctl status {SERVICE_NAME} --no-pager -l")
    if output:
        print(output)


# ─── Main ───────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Zero-touch HTTP Tunnel Server Deployment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 deploy.py              Deploy server to VPS
  python3 deploy.py --status     Check if server is running
  python3 deploy.py --logs       View server logs
  python3 deploy.py --restart    Restart the server
  python3 deploy.py --uninstall  Remove everything
  python3 deploy.py --dry-run    Preview without executing
        """
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview without executing")
    parser.add_argument("--restart", action="store_true", help="Restart the service")
    parser.add_argument("--status", action="store_true", help="Check service status")
    parser.add_argument("--logs", action="store_true", help="Show recent logs")
    parser.add_argument("--uninstall", action="store_true", help="Remove everything from VPS")
    
    args = parser.parse_args()
    
    if args.restart:
        cmd_restart(args.dry_run)
    elif args.status:
        cmd_status(args.dry_run)
    elif args.logs:
        cmd_logs(args.dry_run)
    elif args.uninstall:
        cmd_uninstall(args.dry_run)
    else:
        cmd_deploy(args.dry_run)


if __name__ == "__main__":
    main()