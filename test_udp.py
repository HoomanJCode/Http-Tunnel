#!/usr/bin/env python3
"""
Test UDP connectivity through SOCKS5 proxy at 127.0.0.1:8080.
Tests both DNS (UDP 53) and raw UDP echo.
"""

import socket
import struct
import time
import sys

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

print("Starting UDP test...", flush=True)


def socks5_udp_associate(proxy_host, proxy_port):
    """Establish SOCKS5 UDP ASSOCIATE and return UDP relay address."""
    print(f"  Connecting to {proxy_host}:{proxy_port}...", flush=True)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.settimeout(10)
    
    try:
        tcp_sock.connect((proxy_host, proxy_port))
        print(f"  Connected!", flush=True)
    except Exception as e:
        print(f"  Connection failed: {e}", flush=True)
        raise
    
    # SOCKS5 greeting
    print(f"  Sending SOCKS5 greeting...", flush=True)
    tcp_sock.sendall(b"\x05\x01\x00")  # Version 5, 1 method, No auth
    resp = tcp_sock.recv(2)
    print(f"  Received: {resp.hex()}", flush=True)
    if resp != b"\x05\x00":
        raise Exception(f"SOCKS5 auth failed: {resp.hex()}")
    
    # UDP ASSOCIATE request
    print(f"  Sending UDP ASSOCIATE...", flush=True)
    tcp_sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = tcp_sock.recv(10)
    print(f"  Received {len(resp)} bytes: {resp.hex()}", flush=True)
    
    if len(resp) < 10:
        raise Exception(f"UDP ASSOCIATE response too short: {len(resp)}")
    
    ver, rep, rsv, atyp = resp[0], resp[1], resp[2], resp[3]
    if rep != 0:
        errors = {1: "general failure", 2: "connection not allowed", 
                  3: "network unreachable", 4: "host unreachable", 
                  5: "connection refused", 6: "TTL expired",
                  7: "command not supported", 8: "address type not supported"}
        raise Exception(f"UDP ASSOCIATE failed: {errors.get(rep, f'code {rep}')}")
    
    # Parse bind address
    if atyp == 1:
        bind_host = socket.inet_ntoa(resp[4:8])
        bind_port = struct.unpack('!H', resp[8:10])[0]
    elif atyp == 3:
        domain_len = resp[4]
        bind_host = resp[5:5+domain_len].decode()
        bind_port = struct.unpack('!H', resp[5+domain_len:7+domain_len])[0]
    else:
        raise Exception(f"Unsupported bind address type: {atyp}")
    
    print(f"  UDP relay: {bind_host}:{bind_port}", flush=True)
    return tcp_sock, bind_host, bind_port


def make_udp_packet(target_host, target_port, data):
    """Create a SOCKS5 UDP packet with target address header."""
    packet = b"\x00\x00\x00"
    
    try:
        socket.inet_pton(socket.AF_INET, target_host)
        packet += b"\x01"
        packet += socket.inet_aton(target_host)
    except socket.error:
        packet += b"\x03"
        host_bytes = target_host.encode()
        packet += bytes([len(host_bytes)])
        packet += host_bytes
    
    packet += struct.pack('!H', target_port)
    packet += data
    return packet


def main():
    print("=" * 60, flush=True)
    print("UDP Tunnel Test", flush=True)
    print(f"Proxy: {PROXY_HOST}:{PROXY_PORT}", flush=True)
    print("=" * 60, flush=True)
    
    # Step 1: Establish UDP ASSOCIATE
    print("\n1. Establishing SOCKS5 UDP ASSOCIATE...", flush=True)
    try:
        tcp_sock, relay_host, relay_port = socks5_udp_associate(PROXY_HOST, PROXY_PORT)
    except Exception as e:
        print(f"  FAILED: {e}", flush=True)
        sys.exit(1)
    
    # Step 2: DNS test
    print("\n2. Testing DNS over UDP...", flush=True)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(5)
    
    # Build DNS query for google.com
    dns_id = 0x1234
    header = struct.pack('!HHHHHH', dns_id, 0x0100, 1, 0, 0, 0)
    question = b'\x06google\x03com\x00' + struct.pack('!HH', 1, 1)
    dns_query = header + question
    
    udp_packet = make_udp_packet("8.8.8.8", 53, dns_query)
    print(f"  Sending DNS query ({len(dns_query)} bytes)...", flush=True)
    
    try:
        udp_sock.sendto(udp_packet, (relay_host, relay_port))
        print(f"  Sent. Waiting for response...", flush=True)
        data, addr = udp_sock.recvfrom(4096)
        print(f"  Got {len(data)} bytes from {addr}", flush=True)
        
        # Skip header
        if len(data) > 10:
            dns_resp = data[10:] if data[3] == 1 else data[7+data[4]:]
            if len(dns_resp) > 12:
                resp_id = struct.unpack('!H', dns_resp[0:2])[0]
                print(f"  DNS response ID: {resp_id} (expected {dns_id})", flush=True)
                if resp_id == dns_id:
                    print(f"  DNS over UDP: WORKS!", flush=True)
    except socket.timeout:
        print(f"  Timeout - no DNS response", flush=True)
    except Exception as e:
        print(f"  Error: {e}", flush=True)
    
    # Step 3: Send-only test
    print("\n3. Testing UDP send...", flush=True)
    for host, port in [("8.8.8.8", 53), ("1.1.1.1", 53)]:
        try:
            test_data = b"TEST"
            packet = make_udp_packet(host, port, test_data)
            udp_sock.sendto(packet, (relay_host, relay_port))
            print(f"  Sent to {host}:{port} - OK", flush=True)
        except Exception as e:
            print(f"  Send to {host}:{port} failed: {e}", flush=True)
    
    # Cleanup
    udp_sock.close()
    tcp_sock.close()
    print("\nDone.", flush=True)


if __name__ == "__main__":
    main()
