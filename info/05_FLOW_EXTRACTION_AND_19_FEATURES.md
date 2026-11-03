# Flow Extraction, Feature Engineering & TLS Fingerprinting
## Packet Segmentation, 19 Canonical Features & JA3

This document explains how raw byte streams from `.pcap` and `.pcapng` files are validated, segmented into bidirectional network conversations (flows), converted into 19 statistical metrics, and fingerprinted via unencrypted TLS handshakes.

---

## 1. Raw PCAP Validation & Parsing

The flow extraction pipeline in `backend/app/extractor.py` and `src/lib/pcapExtractor.ts` accepts standard packet capture files. Before extraction, each file undergoes strict validation:

1. **Extension Check:** Must end in `.pcap` or `.pcapng` (case-insensitive).
2. **File Size Bound:** Maximum size limit is enforced at **100 MB** (`104,857,600 bytes`).
3. **Magic Header Verification:** Inspects the first 4 bytes of the global header:
   * Standard PCAP (Little Endian): `0xA1B2C3D4`
   * Standard PCAP (Big Endian): `0xD4C3B2A1`
   * Nanosecond PCAP: `0xA1B23C4D` or `0x4D3CB2A1`
   * PCAPNG Section Header Block: `0x0A0D0D0A`

Corrupt or empty files are rejected immediately with descriptive error responses (`PcapValidationError`), preventing denial-of-service against the IDS parser.

---

## 2. Bidirectional 5-Tuple & Flow Timeouts

In network engineering, individual packets are discrete units, but intrusion detection requires evaluating **conversations**. 

### The 5-Tuple Key:
Packets are grouped into bidirectional sessions using the canonical 5-tuple:
$$\text{Key} = \big(\min(\text{IP}_A, \text{IP}_B), \min(\text{Port}_A, \text{Port}_B), \max(\text{IP}_A, \text{IP}_B), \max(\text{Port}_A, \text{Port}_B), \text{Protocol}\big)$$

The first packet observed sets the **Forward** direction (`Source -> Destination`). Reply packets in reverse are mapped to the **Backward** direction (`Destination -> Source`).

### Flow Segmentation Timeouts:
To prevent unbounded memory growth and ensure that long attacks are flagged in real time, flows are segmented using two strict timeout thresholds (configured in `config.yaml`):

```text
First Packet Arrives
       |
       +---> [ Packet Time - Last Packet Time > Idle Timeout (30s) ? ]
       |        |
       |       YES ---> Flow Terminated (Inactive / Closed)
       |
       +---> [ Current Packet Time - Flow Start Time > Active Timeout (120s) ? ]
                |
               YES ---> Flow Segmented & Flushed for Inspection
```

* **Idle Timeout ($T_{\text{idle}} = 30.0\text{s}$):** If no packet traverses a flow for 30 consecutive seconds, the connection is considered finished and is emitted to the detection pipeline.
* **Active Timeout ($T_{\text{active}} = 120.0\text{s}$):** If an active continuous stream runs for 120 seconds (e.g., an ongoing volumetric DoS flood or large file exfiltration), it is segmented and flushed every 120s so statistical anomalies are evaluated without waiting for the attack to conclude.

---

## 3. The 19 Canonical Flow Features Dictionary

The table below provides the authoritative dictionary of all 19 features computed identically by both the live PCAP extractor and the offline training script:

### Group A: Flow Identifiers & Duration
1. **`destination_port` (int):** The TCP/UDP transport port of the destination service. Identifies whether the target is a sensitive service (e.g., SSH port 22, RDP port 3389, Database port 3306) or standard web traffic (port 80/443).
2. **`protocol` (int):** The IP layer protocol number: `6` for TCP, `17` for UDP, `1` for ICMP.
3. **`flow_duration` (float):** The total elapsed time between the first and last packet of the flow segment, measured in microseconds ($\mu\text{s}$). Short bursts indicate scans or brute-force attempts; long durations indicate persistent sessions or Slowloris.

### Group B: Volume & Byte Distributions
4. **`total_fwd_packets` (int):** Number of packets transmitted from initiator to receiver.
5. **`total_bwd_packets` (int):** Number of response packets transmitted back from receiver to initiator. In DoS floods with spoofed IPs, `total_bwd_packets` is typically zero.
6. **`total_length_of_fwd_packets` (float):** Total byte payload and headers transmitted in the forward direction.
7. **`total_length_of_bwd_packets` (float):** Total byte payload and headers returned in the backward direction.
8. **`min_packet_length` (float):** Length in bytes of the smallest packet observed in the flow.
9. **`max_packet_length` (float):** Length in bytes of the largest packet observed in the flow.
10. **`packet_length_mean` (float):** Arithmetic average of packet lengths across all packets in the flow.
11. **`packet_length_std` (float):** Standard deviation of packet lengths:
    $$\sigma = \sqrt{\frac{1}{N} \sum_{i=1}^{N} (L_i - \bar{L})^2}$$
    Normal HTTP traffic exhibits high standard deviation (small ACK packets mixed with large 1500-byte data packets). Automated flood tools often exhibit $\sigma \approx 0$ due to sending fixed-size packets.

### Group C: Transmission Rates & Inter-Arrival Times
12. **`flow_bytes_s` (float):** Byte throughput per second:
    $$\text{flow\_bytes\_s} = \frac{\text{total\_length\_of\_fwd\_packets} + \text{total\_length\_of\_bwd\_packets}}{\max(\text{flow\_duration} \times 10^{-6}, 10^{-6})}$$
13. **`flow_packets_s` (float):** Packet rate per second:
    $$\text{flow\_packets\_s} = \frac{\text{total\_fwd\_packets} + \text{total\_bwd\_packets}}{\max(\text{flow\_duration} \times 10^{-6}, 10^{-6})}$$
    This is one of the highest-importance features for distinguishing high-rate DoS floods from human browsing.
14. **`flow_iat_mean` (float):** Mean Inter-Arrival Time between consecutive packets across the entire flow, measured in microseconds:
    $$\bar{\tau} = \frac{1}{N - 1} \sum_{i=2}^{N} (t_i - t_{i-1})$$
    Floods have microsecond IATs ($\bar{\tau} < 100\,\mu\text{s}$), whereas Slowloris attacks deliberately stretch IATs to several seconds.

### Group D: TCP Control Flag Counters
15. **`fin_flag_count` (int):** Count of packets carrying the TCP FIN (Finish) flag.
16. **`syn_flag_count` (int):** Count of packets carrying the TCP SYN (Synchronize) flag. Crucial for detecting SYN floods and stealthy port scans (Nmap `-sS`).
17. **`rst_flag_count` (int):** Count of packets carrying the TCP RST (Reset) flag. Indicates aborted sessions or scans hitting closed server ports.
18. **`psh_flag_count` (int):** Count of packets carrying the TCP PSH (Push) flag, requesting immediate buffer flushing to application memory.
19. **`ack_flag_count` (int):** Count of packets carrying the TCP ACK (Acknowledgment) flag. Normal TCP handshakes maintain a balanced SYN/ACK ratio.

---

## 4. Encrypted Traffic Profiling: TLS JA3 & SNI Fingerprinting

Over 85% of modern enterprise network traffic is encrypted with TLS/HTTPS. While full deep packet inspection of encrypted application data requires decryption keys, the initial TLS connection setup occurs in **unencrypted plaintext**.

The flow extractor in `backend/app/extractor.py` intercepts this handshake via `parse_tls_client_hello()`:

```text
TCP 3-Way Handshake
       |
       v
[ Client -> Server: TLS Record Type 0x16 (Handshake), Message 0x01 (ClientHello) ]
       |
       +---> Extracted in Plaintext:
             1. TLS Protocol Version (e.g., TLS 1.2 = 771, TLS 1.3 = 772)
             2. Cipher Suites Offered (e.g., [4865, 4866, 49195, ...])
             3. TLS Extensions Supported (e.g., [0, 10, 11, 13, 43, 51])
             4. Supported Elliptic Curve Groups (e.g., [29, 23, 24])
             5. Elliptic Curve Point Formats (e.g., [0])
             6. Server Name Indication (SNI) (e.g., "login.corp.internal")
```

### The JA3 Fingerprint Construction:
1. The extracted fields are concatenated in order into a comma-delimited string:
   $$\text{JA3\_String} = \text{SSLVersion},\text{CipherSuites},\text{Extensions},\text{EllipticCurves},\text{PointFormats}$$
2. The MD5 cryptographic hash of the string is computed:
   $$\text{JA3\_Hash} = \text{MD5}(\text{JA3\_String})$$

### Why JA3 is Powerful for IDS:
Standard web browsers (Chrome, Firefox, Safari) and common malware packages (Cobalt Strike beacons, Metasploit stagers, Python attack scripts) each utilize distinct TLS client libraries and default cipher lists. 
Even when the attacker uses HTTPS encryption to hide malicious payloads, their **JA3 hash fingerprint** reveals the client software signature, enabling attribution and detection.
