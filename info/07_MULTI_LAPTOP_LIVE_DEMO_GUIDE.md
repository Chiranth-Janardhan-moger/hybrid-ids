# Multi-Laptop Live Demonstration & Cross-Network Attack Testing
## Hosting on Laptop A & Attacking from Laptop B

This guide explains what happens when you host the Hybrid IDPS server on one computer (Laptop A) and an external attacker (Laptop B, e.g., your friend or an examiner) attacks your machine across the network.

---

## 1. Direct Answer: What Happens?

The server in `server.ts` binds to `0.0.0.0:3000`, which means it listens on **all active network interfaces** (localhost `127.0.0.1` and your physical Wi-Fi/Ethernet LAN IP like `192.168.1.50`).

When your friend configures her attack script or tools to target your machine's IP (`http://<YOUR_IP>:3000`):

1. **Physical Network Transmission:** Real TCP/IP packets leave Laptop B's network card, traverse the local Wi-Fi router or mobile hotspot, and hit Laptop A's network interface on port 3000.
2. **Real Client IP Detection:** Express reads the genuine network origin from the underlying TCP socket:
   ```typescript
   const attackerIp = req.socket.remoteAddress?.replace(/^::ffff:/, '');
   // Result: Laptop B's real LAN IP, e.g., 192.168.1.75
   ```
3. **If Block Mode is OFF (Monitor Mode / IDS):**
   * The query is inspected by Layer 1 (Suricata), Layer 2 (ML), and Layer 3 (Honeypot/Entropy).
   * Threats are identified and alerts are logged to the database.
   * **Action:** `ALLOWED_UNBLOCKED` (`HTTP 200 OK`). Her traffic reaches the server, but your dashboard shows live red threat alerts coming from her IP.
4. **If Block Mode is ON (Active Prevention Mode / IPS):**
   * **First Attack:** Detected by Layer 1, 2, or 3. The connection is terminated with **`HTTP 403 Forbidden`**.
   * **Stateful Quarantine Enrollment:** Laptop B's real IP (`192.168.1.75`) is immediately blacklisted in the **Layer 0 In-Memory Quarantine Cache**.
   * **Subsequent Requests:** When Laptop B sends any subsequent query, **Layer 0 drops it in 0.01 ms** before Suricata or ML are ever invoked (`HTTP 403 QUARANTINED`).

---

## 2. Three Practical Approaches for the Live Demo

You can execute a cross-laptop demonstration using three distinct approaches, ranging from simple scripted verification to live raw penetration testing:

### Approach 1: Multi-Laptop Simulation via `live_demo.py` (Recommended for Vivas)
* **Setup:**
  1. Connect both Laptop A (Host) and Laptop B (Attacker) to the same Wi-Fi router or phone hotspot.
  2. On Laptop A, find your LAN IP address:
     ```powershell
     ipconfig
     # Note down the "IPv4 Address", e.g., 192.168.1.50
     ```
  3. Start the server on Laptop A:
     ```powershell
     npm run dev
     ```
  4. On Laptop B, install nothing except Python. Run `live_demo.py` pointing to Laptop A's IP:
     ```powershell
     python live_demo.py --url http://192.168.1.50:3000 --set-block on
     ```
* **What Happens:**
  * Laptop B streams 16 multi-layer queries (Safe queries, SQLi, Log4j, SYN floods, Slowloris, Decoys).
  * Laptop A's SOC dashboard updates live in real-time on your screen.
  * Laptop B's terminal displays real-time verdicts (`HTTP 200 ALLOWED`, `HTTP 403 BLOCKED`, `HTTP 403 QUARANTINED`).

---

### Approach 2: Direct Browser & CLI Attack (No Python Required on Laptop B)
Your friend does not even need to run a script. She can attack your server directly using standard web browsers or command-line utilities:

#### Test A: Trigger Layer 3B (Zero-Trust Honeypot Decoy)
* On Laptop B, open Google Chrome or Edge and navigate to:
  ```text
  http://192.168.1.50:3000/.env
  ```
  or
  ```text
  http://192.168.1.50:3000/.aws/credentials
  ```
* **Result:**
  * Laptop A intercepts Laptop B's real IP via `req.socket.remoteAddress`.
  * Laptop B receives:
    ```json
    {
      "honeypot_trap": true,
      "action": "BLOCKED",
      "risk_score": 100,
      "detail": "Zero-Trust Canary Accessed: /.env"
    }
    ```
  * Laptop B's IP is automatically quarantined!

#### Test B: Trigger Layer 1 (Suricata SQL Injection) via cURL
* On Laptop B (Terminal / PowerShell):
  ```bash
  curl -X POST http://192.168.1.50:3000/api/ips/query \
    -H "Content-Type: application/json" \
    -d '{"payload_summary": "SELECT * FROM users WHERE id=1 OR 1=1 UNION SELECT password FROM admin", "label": "Direct SQLi Exploit"}'
  ```
* **Result:**
  * Suricata matches `SID 2010935 (SQL Injection)`.
  * Returns `HTTP 403 Forbidden` (`action: BLOCKED`).

---

### Approach 3: Realistic Penetration Testing Tools (Nmap / Metasploit / Python Requests)
If an examiner asks: *"Can we use real security tools like Nmap or Sqlmap?"*

Yes:
1. **Nmap Scan from Laptop B:**
   ```bash
   nmap -sS -p 80,443,3000 192.168.1.50
   ```
   * Fast port scanning triggers high SYN flag ratios and microsecond inter-arrival times.
   * Captured packets processed through the flow pipeline trigger **Tier 2 (Random Forest ML Anomaly)** with `risk_score >= 80`.
2. **Wireshark Capture & Replay:**
   * Laptop B attacks Laptop A while Wireshark records the interface.
   * Save the capture as `attack_capture.pcap`.
   * Drag and drop `attack_capture.pcap` directly into the web UI at `http://localhost:3000/upload`.
   * The hybrid pipeline validates the 5-tuples, extracts the 19 features, and correlates the multi-stage attack.

---

## 3. Critical Troubleshooting & Network Checklist

If Laptop B cannot connect to Laptop A, verify the following three common network issues:

### 1. Windows Defender Firewall (Most Common Issue)
By default, Windows blocks incoming connections on port 3000 from external network devices.
* **Fix on Laptop A (Run in Admin PowerShell):**
  ```powershell
  New-NetFirewallRule -DisplayName "Hybrid-IDS-Port3000" -Direction Inbound -LocalPort 3000 -Protocol TCP -Action Allow
  ```
* Alternatively, set your Wi-Fi network profile to **Private** in Windows Settings.

### 2. Wi-Fi "AP / Client Isolation" (College / Campus Networks)
Many university and enterprise Wi-Fi networks enable **Client Isolation**, which forbids wireless devices from talking directly to each other.
* **Solution:** Turn on a mobile hotspot on your phone. Connect both laptops to that mobile hotspot. Client isolation is disabled on phone hotspots, allowing direct peer-to-peer communication.

### 3. Verify IP Connectivity First
Before running attack tools, verify basic network reachability from Laptop B:
```powershell
ping 192.168.1.50
curl http://192.168.1.50:3000/api/health
```
If `/api/health` returns `{"status":"ok"}`, the path is clear for the live attack demo.
