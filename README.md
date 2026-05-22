## **README.md**

# HTTP Tunnel - TCP/UDP over HTTP POST

> **⚠️ EXPERIMENTAL - NOT FOR PRODUCTION USE ⚠️**

A proof-of-concept tool that tunnels TCP and UDP traffic through HTTP POST requests, designed for highly restricted networks where only HTTP is allowed. Built through AI-human collaboration using DeepSeek AI.

## ⚠️ Disclaimers & Security Warnings

### 🔴 **CRITICAL WARNINGS**

1. **NOT PRODUCTION READY**: This is experimental software created for educational and research purposes only
2. **SECURITY RISKS**: 
   - Encryption is basic and has NOT been audited by security professionals
   - Vulnerable to man-in-the-middle attacks
   - No certificate pinning or TLS verification by default
   - Session IDs could potentially be brute-forced
3. **NETWORK POLICY VIOLATION**: Using this tool may violate your organization's network policies. Use only on networks you own or have explicit permission to test
4. **NO WARRANTY**: This software comes with absolutely no warranty. See LICENSE file for details
5. **PERFORMANCE LIMITATIONS**: HTTP/1.1 tunneling introduces significant latency and overhead. Not suitable for real-time applications

### 📜 **Legal Notice**

Users are solely responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this software.

---

## 📖 Overview

HTTP Tunnel creates a virtual TCP/UDP connection through HTTP POST requests, allowing you to bypass network restrictions that block everything except HTTP traffic.

### 🎯 Use Cases

- Penetration testing in restricted environments (with proper authorization)
- Educational purposes to understand HTTP tunneling concepts
- Accessing services behind strict HTTP-only firewalls
- Bypassing DNS censorship with server-side DNS resolution
- Research on network restriction bypass techniques

### 🔧 How It Works

```
┌─────────────┐      SOCKS5       ┌─────────────┐      HTTP POST      ┌─────────────┐      TCP/UDP       ┌─────────────┐
│             │                   │             │                     │             │                    │             │
│  Application│ ◄──────────────►  │   Client    │ ◄─────────────────► │   Server    │ ◄────────────────► │  Target     │
│  (curl/ssh) │                   │  (Python)   │                     │  (Python)   │                    │  Service    │
│             │                   │             │                     │             │                    │             │
└─────────────┘                   └─────────────┘                     └─────────────┘                    └─────────────┘
      Local                          Local SOCKS5                        Remote HTTP                         Remote
      Request                        Proxy                               Tunnel Server                       Destination
```

1. **Client** runs a local SOCKS5 proxy
2. Applications connect to this SOCKS5 proxy
3. Client wraps TCP/UDP data in encrypted HTTP POST requests
4. **Server** receives POST requests, extracts data, and connects to the actual destination
5. Responses flow back through HTTP response bodies

### ✨ Key Features

- **DNS Leak Prevention**: Server-side DNS resolution prevents DNS censorship
- **Smart Bypass**: Localhost requests bypass tunnel automatically
- **Zlib Compression**: Reduces bandwidth usage by 50-70% for text protocols
- **Adaptive Keep-Alive**: Exponential backoff reduces idle traffic by 80%
- **Connection Pooling**: HTTP keep-alive for reduced connection overhead
- **QoS Priority**: SSH/HTTP ports get priority over bulk transfers
- **Session Recovery**: Automatic retry with exponential backoff
- **UDP Support**: Full UDP tunneling through HTTP POST
- **Health Checks**: Server health monitoring every 15 seconds
- **Configuration Auto-Cleaning**: Invalid parameters removed, defaults added automatically
- **Configurable Logging**: DEBUG/INFO/WARNING/ERROR levels

---

## 📦 Requirements

### Server
- Python 3.7+
- Linux server with internet access
- Open port for HTTP (configurable)

### Client
- Python 3.7+
- Linux / Termux / Windows (with Python)
- Outbound HTTP access (optionally through HTTP proxy)

### Python Dependencies
```bash
pip install cryptography requests
```

---

## 🚀 Quick Start

### 1. Server Setup

```bash
# Clone the repository
git clone https://github.com/HoomanJCode/Http-Tunnel.git
cd Http-Tunnel

# Install dependencies
pip install -r requirements.txt

# Run setup wizard (asks only: PSK key, listen address, compression)
python server.py

# Or with existing config
python server.py
```

**Systemd Service (Linux)**:
```ini
# /etc/systemd/system/http-tunnel.service
[Unit]
Description=HTTP Tunnel Server
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/Http-Tunnel
ExecStart=/usr/bin/python3 /opt/Http-Tunnel/server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now http-tunnel.service
```

### 2. Client Setup

#### Linux Desktop/Server
```bash
# Clone the repository
git clone https://github.com/HoomanJCode/Http-Tunnel.git
cd Http-Tunnel

# Install dependencies
pip install -r requirements.txt

# Run setup wizard
python client.py
# Enter:
#   PSK key (same as server)
#   SOCKS5 listen: 127.0.0.1:1080 (default)
#   Server URL: http://your-server.com:8080/tunnel
#   Outbound proxy: (leave empty if none)
#   DNS mode: server (recommended for censored networks)

# IMPORTANT: Use --socks5-hostname to prevent DNS leaks
curl --socks5-hostname 127.0.0.1:1080 --ipv4 https://example.com

# For SSH
ssh -o ProxyCommand='nc --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p' user@remote-host
```

#### Termux (Android)
```bash
# Install Termux from F-Droid (NOT Google Play)
pkg update && pkg upgrade
pkg install python git

# Clone and setup
git clone https://github.com/HoomanJCode/Http-Tunnel.git
cd Http-Tunnel
pip install cryptography requests

# Run setup wizard
python client.py

# Use with curl in Termux
pkg install curl
curl --socks5-hostname 127.0.0.1:1080 --ipv4 https://example.com
```

---

## ⚙️ Configuration

### Server Configuration (`server_config.json`)
```json
{
    "encryption_key": "your-secret-psk-key",
    "listen": "0.0.0.0:8080",
    "max_post_bytes": 5242880,
    "tcp_timeout": 60,
    "udp_timeout": 120,
    "cleanup_interval": 30,
    "compression": true,
    "log_level": "INFO"
}
```

### Client Configuration (`client_config.json`)
```json
{
    "encryption_key": "your-secret-psk-key",
    "socks_listen": "127.0.0.1:1080",
    "server_url": "http://your-server:8080/tunnel",
    "outbound_http_proxy": "",
    "dns_mode": "server",
    "max_post_bytes": 5242880,
    "http_timeout": 30,
    "heartbeat_interval": 1,
    "batch_wait": 0.01,
    "reconnect_delay": 0.5,
    "compression": true,
    "bypass_local": true,
    "log_level": "INFO"
}
```

> **Note**: Configuration files are automatically cleaned on load. Invalid parameters are removed and missing defaults are added. Each config file only contains parameters relevant to its role.

### Server Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `encryption_key` | (required) | Pre-shared key for encrypting tunnel traffic |
| `listen` | `0.0.0.0:8080` | Server listen address and port |
| `max_post_bytes` | `5242880` | Maximum POST request size (5MB) |
| `tcp_timeout` | `60` | TCP session timeout in seconds |
| `udp_timeout` | `120` | UDP session timeout in seconds |
| `cleanup_interval` | `30` | Session cleanup check interval |
| `compression` | `true` | Enable/disable zlib compression |
| `log_level` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |

### Client Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `encryption_key` | (required) | Pre-shared key (must match server) |
| `socks_listen` | `127.0.0.1:1080` | Local SOCKS5 proxy address |
| `server_url` | `http://localhost:8080/tunnel` | Tunnel server URL |
| `outbound_http_proxy` | `""` | Optional HTTP proxy for outbound |
| `dns_mode` | `server` | DNS resolution: `server` (no leaks) or `local` |
| `max_post_bytes` | `5242880` | Maximum POST request size (5MB) |
| `http_timeout` | `30` | HTTP request timeout in seconds |
| `heartbeat_interval` | `1` | Keepalive heartbeat interval (adaptive 1s-30s) |
| `batch_wait` | `0.01` | Data batching delay for efficiency |
| `reconnect_delay` | `0.5` | Delay between reconnection attempts |
| `compression` | `true` | Enable/disable zlib compression |
| `bypass_local` | `true` | Bypass tunnel for localhost connections |
| `log_level` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |

---

## 🔒 Security Considerations

1. **Always use HTTPS**: Change `server_url` to `https://` and use a reverse proxy with TLS
2. **Strong PSK**: Use a long, random pre-shared key (minimum 32 characters)
3. **Firewall rules**: Restrict server port access to trusted IPs only
4. **Reverse proxy**: Use nginx with rate limiting:
   ```nginx
   location /tunnel {
       limit_req zone=tunnel burst=5 nodelay;
       proxy_pass http://127.0.0.1:8080;
   }
   ```
5. **Regular key rotation**: Change PSK periodically
6. **DNS leak prevention**: Always use `dns_mode: server` and `curl --socks5-hostname`

---

## 🛠️ Troubleshooting

### Connection Refused (curl error 97)
- Use `--socks5-hostname` instead of `--socks5` to send domain names to proxy
- Add `--ipv4` flag to avoid IPv6 issues
- Verify server is running and port is open

### DNS Leaks / Censored DNS
- Set `dns_mode: server` in client config
- Always use `curl --socks5-hostname`
- Check client log shows "DNS: server"

### Timeouts
- Increase `http_timeout` for slow connections (default 30s)
- Check outbound proxy settings
- Verify network allows HTTP POST to your server

### IPv6 Issues
- Use `--ipv4` flag with curl
- Server must have IPv6 connectivity if connecting to IPv6 destinations

### Slow Performance
- Enable compression (`compression: true`)
- Increase `max_post_bytes` for larger chunks
- Decrease `batch_wait` for lower latency
- Decrease `heartbeat_interval` for more responsive connections

### Server Crashes
- Update to latest version with ConnectionResetError handling
- Check server logs for error details
- Restart with systemd service for auto-recovery

---

## 🤝 Contributing

### This is a "Vibe Coding" Project

This project was created through "vibe coding" - an experimental development approach using **DeepSeek AI** to generate code based on natural language descriptions and iterative refinement. The entire codebase was written through AI-human collaboration over multiple sessions.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**:
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Test thoroughly** in your environment
5. **Submit a Pull Request** with:
   - Description of changes
   - Test cases
   - Any configuration changes needed

### Development Guidelines

- Keep dependencies minimal (`cryptography`, `requests`)
- Configuration auto-cleaning on load (remove invalid, add defaults)
- Log all errors with appropriate levels
- Don't log sensitive data (keys, credentials)
- Test with both direct and proxy connections
- Verify TCP and UDP functionality
- Test with `--socks5-hostname` for DNS leak prevention

### Areas for Improvement

- [ ] HTTPS/TLS support with certificate verification
- [ ] WebSocket support for better performance
- [ ] HTTP/2 multiplexing
- [ ] Authentication beyond PSK
- [ ] Bandwidth throttling
- [ ] Connection pooling optimization
- [ ] Better IPv6 support
- [ ] GUI configuration tool
- [ ] Docker containers
- [ ] Performance benchmarks

---

## 📊 Limitations

- **High Latency**: 50-500ms added per request due to HTTP overhead
- **No Stream Multiplexing**: Each TCP connection requires its own HTTP request loop
- **HTTP/1.1 Only**: No WebSocket or HTTP/2 support
- **Basic Encryption**: Not suitable for highly sensitive data
- **Sequential Delivery**: Packets may be reordered under high load

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **DeepSeek AI** - Code generation and development assistance
- The Python community for excellent libraries
- Security researchers who document tunneling techniques
- Everyone who tests and reports bugs

---

## ⭐ Star History

If you find this project interesting or useful, please consider giving it a star ⭐

---

> **Remember**: This tool is for educational and authorized testing purposes only. The authors are not responsible for any misuse or damages. Always respect network policies and obtain proper authorization before testing.
```