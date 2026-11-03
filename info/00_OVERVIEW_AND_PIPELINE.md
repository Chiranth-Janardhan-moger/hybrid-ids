# Hybrid Intrusion Detection & Prevention System (Hybrid IDPS)
## Architecture & Pipeline Overview

This document provides a high-level technical architectural overview of the Hybrid Network Intrusion Detection and Prevention System (Hybrid IDPS). It details how raw network packets enter the system, how each inspection layer evaluates traffic, and how final mitigation verdicts are enforced.

---

## 1. System Mission & Core Philosophy

Traditional enterprise perimeter security suffers from two complementary failure modes:
1. **Signature-Only IDS (e.g., standalone Snort or Suricata):** Excels at deterministic matching against known application-layer exploits (SQL Injection, Log4j, Remote Code Execution) with near-zero false alarms. However, it is completely blind to novel zero-day attacks, modified payloads, and volumetric behavioral anomalies (such as SYN floods or Slowloris starvation).
2. **Anomaly / Machine Learning-Only IDS:** Flags behavioral deviations and volumetric shifts, but suffers from high false-positive rates. In real-world enterprise networks where attack prevalence is low (often less than 1%), even a 2% false positive rate collapses analyst trust due to alert fatigue (the Base-Rate Fallacy).

**The Hybrid Solution:**
This system implements a **cascading multi-tier defense**. High-confidence deterministic signatures run first. Unmatched traffic cascades into a calibrated Random Forest machine learning classifier trained on canonical flow statistics. Both detection streams are then unified by a 4-factor risk scoring engine that correlates multi-stage kill chains. Finally, an active firewall layer enforces inline blocking or stateful quarantine.

---

## 2. End-to-End Packet Processing Pipeline

Traffic entering the system traverses an ordered sequence of inspection tiers. The diagram below illustrates the exact control flow:

```text
Raw Ingress Packet Stream (.pcap / .pcapng or live stream)
       |
       v
+-------------------------------------------------------------+
| LAYER 0: Stateful In-Memory IP Auto-Quarantine Pre-Filter   |
| - Sub-millisecond hash lookup (0.01 ms)                     |
| - If source IP is banned and Block Mode is ON -> DROP (403) |
+-------------------------------------------------------------+
       | (Clean / Not Quarantined)
       v
+-------------------------------------------------------------+
| FLOW ENGINE: Bidirectional 5-Tuple Segmentation             |
| - Key: (src_ip, src_port, dst_ip, dst_port, protocol)       |
| - Timeouts: Active = 120s, Idle = 30s                       |
| - Computes 19 canonical statistical features                |
| - TLS ClientHello Parser: JA3 MD5 + SNI (port 443)          |
+-------------------------------------------------------------+
       |
       +------------------------------------+
       |                                    |
       v                                    v
+-----------------------------+      +-------------------------------+
| LAYER 1 (TIER 1):           |      | LAYER 3A & 3B:                |
| Suricata Signature DPI      |      | Payload Inspection & Traps    |
| - ET Open rule matching     |      | - Shannon Entropy H(X) >= 4.85|
| - Regex & payload content   |      | - Zero-Trust Honeypot decoys  |
| - 5.0s time window corr.    |      |   (/.env, /admin/config.bak)  |
+-----------------------------+      +-------------------------------+
       |                                    |
  [Match Found?]                            |
       |                                    |
      YES ---> Known Exploit Alert          |
       |                                    |
       NO                                   |
       v                                    v
+-------------------------------------------------------------+
| LAYER 2 (TIER 2): Random Forest Machine Learning Anomaly   |
| - Evaluates ONLY unmatched flows                            |
| - 19 flow features evaluated across 25 decision trees       |
| - Decision threshold tau* = 0.64 (Platt-calibrated)         |
| - Exact tree-path explanation (Delta P feature attribution) |
+-------------------------------------------------------------+
       |
  [P(malicious) >= 0.64?]
       |
      YES ---> ML Anomaly Alert
       |
       NO ---> Benign Flow (Stored in SQLite, 0 Alert)
       |
       +------------------------------------+
                                            |
                                            v
+-------------------------------------------------------------+
| RISK SCORING ENGINE: 4-Factor Heuristic & Campaign Tracker  |
| Score = 100 * (0.40*Sev + 0.30*Conf + 0.20*Beh + 0.10*Ctx)  |
| - Multi-Stage Kill-Chain: Recon + Exploit boosts Ctx -> 1.0 |
| - Classifies into: Low (<30), Medium (30-59), High (60-79), |
|   Critical (>=80)                                           |
+-------------------------------------------------------------+
                                            |
                                            v
+-------------------------------------------------------------+
| ENFORCEMENT & MITIGATION (IPS vs IDS Mode)                  |
| - Block Mode OFF (IDS): Log alert, pass traffic (HTTP 200)  |
| - Block Mode ON (IPS): Drop packet (HTTP 403), record log,  |
|   and auto-enroll source IP into Layer 0 Quarantine cache   |
+-------------------------------------------------------------+
```

---

## 3. Defense Tiers Summary

| Defense Tier | Component Name | Technology | Primary Target | Latency Profile |
| :--- | :--- | :--- | :--- | :--- |
| **Layer 0** | IP Auto-Quarantine Pre-Filter | In-memory hash set / LRU cache | Repeat attackers, active ban list | ~0.01 ms |
| **Layer 1 (Tier 1)** | Signature Inspection | Suricata + ET Open rule engine | Known exploits (SQLi, Log4j, RCE, scans) | ~1.2 - 5.0 ms |
| **Layer 2 (Tier 2)** | Flow Anomaly Classifier | Balanced Random Forest (25 trees) | Volumetric floods, zero-days, slowloris | ~27.27 microseconds |
| **Layer 3A** | Obfuscation Detector | Shannon Entropy DPI ($H(X)$) | Encrypted shellcode, packed webshells | ~0.15 ms |
| **Layer 3B** | Zero-Trust Decoy Traps | Honeypot route interceptor | Recon probes targeting sensitive files | ~0.05 ms |

---

## 4. Dual Operational Modes: IDS vs IPS

The system can operate in either of two operational postures, switchable dynamically at runtime:

### A. Monitor Mode (Passive IDS)
* **Block Mode Switch:** `OFF`
* **Network Behavior:** All traffic is allowed through to destination servers (`HTTP 200 OK`).
* **Detection Activity:** All inspection engines run concurrently. Alerts are generated, risk scores are calculated, and incident records are committed to the SQLite database.
* **Use Case:** Safe baseline monitoring, initial deployment tuning, and avoiding unintended false-positive production outages.

### B. Active Prevention Mode (Inline IPS)
* **Block Mode Switch:** `ON`
* **Network Behavior:** When any tier classifies a transaction as malicious:
  1. The TCP session or HTTP request is dropped immediately (`HTTP 403 Forbidden`).
  2. The incident is logged with its exact detection breakdown.
  3. The attacker's source IP address is automatically enrolled in the **Layer 0 Quarantine Cache**.
  4. Any subsequent packet from that IP is dropped in sub-millisecond memory lookup before reaching deeper inspection engines.
* **Safe Traffic:** Transactions that pass all tiers clean are passed to production servers (`HTTP 200 OK`) without latency degradation.

---

## 5. Input Data Formats Supported

The engine processes network telemetry across two interfaces:
1. **Offline PCAP / PCAPNG Upload:**
   * Accepts standard `.pcap` and `.pcapng` capture files up to 100 MB.
   * Validates global pcap magic headers (`0xA1B2C3D4`, `0x0A0D0D0A`).
   * Extracts flows, runs Suricata and ML in batch, and populates the forensic database.
2. **Live HTTP / Flow Stream:**
   * Accepts live micro-batches or individual requests via `POST /api/ips/query`.
   * Simulates full live inline firewall enforcement in real time.

---

## 6. Organization of Study Modules

To master every layer of this system, read the dedicated modules in the `info/` directory in sequence:

1. `01_TIER_1_SURICATA_SIGNATURE_ENGINE.md` - Deep dive into Suricata rule evaluation, SID matching, and 5-tuple time correlation.
2. `02_TIER_2_MACHINE_LEARNING_ENGINE.md` - Random Forest anomaly classification, the 19 features, threshold calibration, and tree-path explainability.
3. `03_HOW_IT_IS_HYBRID.md` - Why signature and ML must be paired, the Base-Rate Fallacy proof, and the cascading execution path.
4. `04_MULTI_TIER_FILTERING_AND_ACTIVE_PREVENTION.md` - Layer 0 quarantine, Layer 3 entropy/honeypots, and active blocking mechanics.
5. `05_FLOW_EXTRACTION_AND_19_FEATURES.md` - Active/idle flow timeouts, exact mathematical definitions of all 19 features, and TLS JA3 fingerprinting.
6. `06_RISK_SCORING_AND_CAMPAIGN_CORRELATION.md` - The 4-factor risk formula, multi-stage kill-chain linking, and SOC triage lifecycle.
