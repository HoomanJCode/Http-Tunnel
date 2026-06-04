#!/usr/bin/env python3
"""
Zero-touch VPS deployment for HTTP Tunnel Server.
Works with local .env or GitHub Actions secrets.

Local usage:
    python3 deploy.py

GitHub Actions usage:
    Set secrets in repository: VPS_HOST, VPS_USER, VPS_PORT,
    VPS_SSH_PRIVATE_KEY, ENCRYPTION_KEY, LISTEN_PORT, LOG_LEVEL
"""

import os
import sys
import argparse
import subprocess
import tempfile
import textwrap
from pathlib import Path


def load_env():
    """Load configuration from .env (local) or GitHub Actions secrets."""
    # GitHub Actions sets GITHUB_ACTIONS=true automatically
    is_github = os.getenv("GITHUB_ACTIONS", "").lower() == "true"
    
    if is_github:
        # GitHub Actions: secrets are already in environment
        required = ["VPS_HOST", "VPS_USER", "ENCRYPTION_KEY"]
        missing = [k for k in required if not os.getenv(k)]
        if missing:
            print(f"❌ Missing secrets: {', '.join(missing)}")
            print("   Set them in GitHub repository: Settings > Secrets and variables > Actions")
            sys.exit(1)
        print("✅ Using GitHub Actions secrets")
        return
    
    # Local: try python-dotenv, fallback to manual parsing
    env_file = Path(".env")
    if not env_file.exists():
        print("⚠️  No .env file found. Using environment variables only.")
        return
    
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("✅ Loaded .env file")
    except ImportError:
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    val = val.strip().strip('"').strip("'")
                    if key and val:
                        os.environ[key] = val
        print("✅ Loaded .env file (manual parse)")


# Load config immediately
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
    """Generate complete bash script for VPS setup."""
    
    script = textwrap.dedent(f'''\
    #!/bin/bash
    set -e

    PROJECT_DIR="{PROJECT_DIR}"
    SERVICE_NAME="{SERVICE_NAME}"
    REPO_URL="{REPO_URL}"
    LISTEN_PORT="{LISTEN_PORT}"

    echo "=========================================="
    echo "  HTTP Tunnel Server - Auto Deploy"
    echo "=========================================="
    echo "  Server: $(hostname)"
    echo "  Time:   $(date)"
    echo "=========================================="
    echo ""

    # ─── Disk Space Check ─────────────────────────────
    echo "[1/8] 💾 Checking disk space..."
    AVAILABLE=$(df -BG "$PROJECT_DIR" 2>/dev/null | tail -1 | awk '{{print $4}}' | sed 's/G//')
    if [ -z "$AVAILABLE" ]; then
        AVAILABLE=$(df -BG /opt 2>/dev/null | tail -1 | awk '{{print $4}}' | sed 's/G//')
    fi
    if [ -n "$AVAILABLE" ] && [ "$AVAILABLE" -lt 1 ]; then
        echo "❌ Less than 1GB disk space ($AVAILABLE GB). Aborting."
        exit 1
    fi
    echo "  ✅ Disk space OK ($AVAILABLE GB available)"

    # ─── System Setup ──────────────────────────────────
    echo "[2/8] 📦 Installing packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv git curl 2>&1 | tail -1

    # ─── Firewall ──────────────────────────────────────
    echo "[3/8] 🔥 Opening port {LISTEN_PORT}..."
    ufw status | grep -q "$LISTEN_PORT/tcp" || {{
        ufw allow $LISTEN_PORT/tcp comment "HTTP Tunnel Server" > /dev/null
        echo "  ✅ Port {LISTEN_PORT} opened"
    }}
    echo "  Firewall: $(ufw status | head -1)"

    # ─── Create User ───────────────────────────────────
    echo "[4/8] 👤 Creating service user..."
    if ! id -u tunnel > /dev/null 2>&1; then
        useradd -r -s /usr/sbin/nologin -d /nonexistent -M tunnel
        echo "  ✅ User 'tunnel' created"
    else
        echo "  ✅ User 'tunnel' exists"
    fi

    # ─── Clone Repository ──────────────────────────────
    echo "[5/8] 📥 Deploying code..."
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
    echo "[6/8] ⚙️  Creating .env..."
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
    echo "[7/8] 🐍 Setting up Python..."
    cd "$PROJECT_DIR"
    rm -rf venv
    python3 -m venv venv
    "$PROJECT_DIR/venv/bin/pip" install --upgrade pip -q 2>&1 | tail -1
    "$PROJECT_DIR/venv/bin/pip" install -r requirements.txt -q 2>&1 | tail -1

    "$PROJECT_DIR/venv/bin/python" -c "
    import sys; sys.path.insert(0, '$PROJECT_DIR')
    from http_tunnel.server.tunnel import run_server
    from http_tunnel.crypto import TunnelCrypto
    print('  ✅ Modules loaded')
    "

    # ─── Systemd Service ───────────────────────────────
    echo "[8/8] 🔧 Creating systemd service..."
    cat > /etc/systemd/system/$SERVICE_NAME.service << 'SERVICEEOF'
    [Unit]
    Description=HTTP Tunnel Server
    After=network.target

    [Service]
    Type=simple
    User=tunnel
    WorkingDirectory={PROJECT_DIR}
    Environment=PATH={PROJECT_DIR}/venv/bin:/usr/bin:/bin
    Environment=PYTHONUNBUFFERED=1
    ExecStart={PROJECT_DIR}/venv/bin/python {PROJECT_DIR}/server.py
    Restart=always
    RestartSec=5
    StandardOutput=append:/var/log/{SERVICE_NAME}.log
    StandardError=append:/var/log/{SERVICE_NAME}.log
    NoNewPrivileges=yes
    PrivateTmp=yes
    ProtectSystem=strict
    ProtectHome=yes
    ReadWritePaths={PROJECT_DIR}

    [Install]
    WantedBy=multi-user.target
    SERVICEEOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME --quiet

    # ─── Start ─────────────────────────────────────────
    echo "▶️  Starting..."
    systemctl restart $SERVICE_NAME
    sleep 4

    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "✅ RUNNING on 0.0.0.0:{LISTEN_PORT}"
        systemctl status $SERVICE_NAME --no-pager -l
        echo "📊 Logs:"
        tail -10 /var/log/{SERVICE_NAME}.log 2>/dev/null || true
    else
        echo "❌ FAILED"
        tail -30 /var/log/{SERVICE_NAME}.log 2>/dev/null || true
        journalctl -u $SERVICE_NAME -n 30 --no-pager || true
        exit 1
    fi
    ''')
    
    return script


def generate_uninstall_script():
    """Generate bash script to remove the server."""
    return textwrap.dedent(f'''\
    #!/bin/bash
    set -e
    systemctl stop {SERVICE_NAME} 2>/dev/null || true
    systemctl disable {SERVICE_NAME} 2>/dev/null || true
    rm -f /etc/systemd/system/{SERVICE_NAME}.service
    systemctl daemon-reload
    rm -rf {PROJECT_DIR}
    rm -f /var/log/{SERVICE_NAME}.log
    userdel tunnel 2>/dev/null || true
    ufw delete allow {LISTEN_PORT}/tcp 2>/dev/null || true
    echo "✅ Removed"
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
        subprocess.run(scp_args(script_path, "/tmp/tunnel_deploy.sh"), capture_output=True, text=True)
        success, output = run_remote("bash /tmp/tunnel_deploy.sh")
        if output:
            print(output)
        return success
    finally:
        os.unlink(script_path)


# ─── Commands ───────────────────────────────────────────
def cmd_deploy(dry_run=False):
    if not VPS_HOST:
        print("❌ VPS_HOST not set")
        sys.exit(1)
    if not ENCRYPTION_KEY:
        print("❌ ENCRYPTION_KEY not set")
        sys.exit(1)
    print(f"🚀 Deploying to {VPS_USER}@{VPS_HOST}:{VPS_PORT} (port {LISTEN_PORT})")
    script = generate_deploy_script()
    if upload_and_run(script, dry_run) and not dry_run:
        print(f"\n✅ Done! Client config: SERVER_URL=http://{VPS_HOST}:{LISTEN_PORT}/tunnel")


def cmd_uninstall(dry_run=False):
    if not VPS_HOST:
        sys.exit(1)
    if not dry_run and input("Type 'yes' to confirm: ") != "yes":
        return
    upload_and_run(generate_uninstall_script(), dry_run)


def cmd_status(dry_run=False):
    _, output = run_remote(f"systemctl status {SERVICE_NAME} --no-pager -l; echo ---; tail -20 /var/log/{SERVICE_NAME}.log 2>/dev/null || true")
    if output:
        print(output)


def cmd_logs(dry_run=False):
    _, output = run_remote(f"tail -50 /var/log/{SERVICE_NAME}.log 2>/dev/null || echo 'No logs'")
    if output:
        print(output)


def cmd_restart(dry_run=False):
    _, output = run_remote(f"systemctl restart {SERVICE_NAME} && sleep 2 && systemctl status {SERVICE_NAME} --no-pager -l")
    if output:
        print(output)


# ─── Main ───────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Zero-touch HTTP Tunnel Server Deployment")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--restart", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--logs", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
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