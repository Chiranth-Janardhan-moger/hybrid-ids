# Hybrid IDPS Study Guide & Technical Documentation
## Master Curriculum & Architecture Index

Welcome to the **Hybrid Intrusion Detection & Prevention System (Hybrid IDPS)** technical study guide. This documentation suite is designed for engineers, researchers, and students who want to understand the exact internal mechanics of this hybrid network security platform.

---

## 1. Documentation Curriculum & Reading Order

To build a thorough understanding of the architecture, read the modules in the following recommended order:

| Module File | Topic & Scope | Key Takeaway |
| :--- | :--- | :--- |
| [00_OVERVIEW_AND_PIPELINE.md](file:///D:/Projects/apps/hybrid-ids/info/00_OVERVIEW_AND_PIPELINE.md) | **End-to-End Pipeline & Defense Tiers** | How packets enter the system, traverse Layer 0 to Layer 3, and get filtered or blocked. |
| [01_TIER_1_SURICATA_SIGNATURE_ENGINE.md](file:///D:/Projects/apps/hybrid-ids/info/01_TIER_1_SURICATA_SIGNATURE_ENGINE.md) | **Tier 1: Suricata Signature Inspection** | How Suricata evaluates ET Open rules, matches byte payloads (SQLi, Log4j), and correlates to 5-tuple flows within a 5.0s window. |
| [02_TIER_2_MACHINE_LEARNING_ENGINE.md](file:///D:/Projects/apps/hybrid-ids/info/02_TIER_2_MACHINE_LEARNING_ENGINE.md) | **Tier 2: Random Forest Anomaly Engine** | The 19 statistical flow features, Balanced Random Forest, leak-free temporal day split, tau*=0.64 threshold, and Saabas tree-path XAI. |
| [03_HOW_IT_IS_HYBRID.md](file:///D:/Projects/apps/hybrid-ids/info/03_HOW_IT_IS_HYBRID.md) | **The Hybrid Cascade & Mathematical Justification** | Why Signature-Only fails (56% recall), why ML-Only fails (Base-Rate Fallacy proof), how the cascade hits 96.88% recall, and engine degradation states. |
| [04_MULTI_TIER_FILTERING_AND_ACTIVE_PREVENTION.md](file:///D:/Projects/apps/hybrid-ids/info/04_MULTI_TIER_FILTERING_AND_ACTIVE_PREVENTION.md) | **Active Defense, IPS Blocking & Quarantine** | Layer 0 sub-millisecond (0.01 ms) in-memory IP quarantine pre-filter, Layer 3 Shannon entropy (H(X) >= 4.85), honeypot decoy traps, and HTTP 403 drops. |
| [05_FLOW_EXTRACTION_AND_19_FEATURES.md](file:///D:/Projects/apps/hybrid-ids/info/05_FLOW_EXTRACTION_AND_19_FEATURES.md) | **PCAP Flow Extraction & TLS JA3** | Bidirectional 5-tuple segmentation, active (120s) and idle (30s) timeouts, exact mathematical definitions of all 19 features, and unencrypted TLS ClientHello JA3/SNI parsing. |
| [06_RISK_SCORING_AND_CAMPAIGN_CORRELATION.md](file:///D:/Projects/apps/hybrid-ids/info/06_RISK_SCORING_AND_CAMPAIGN_CORRELATION.md) | **4-Factor Risk Engine & Kill-Chain Tracking** | 100*(0.40Sev + 0.30Conf + 0.20Beh + 0.10Ctx) formula, 60-second sliding campaign correlation, automatic context boost to 1.00, and SOC triage lifecycle. |
| [07_MULTI_LAPTOP_LIVE_DEMO_GUIDE.md](file:///D:/Projects/apps/hybrid-ids/info/07_MULTI_LAPTOP_LIVE_DEMO_GUIDE.md) | **Multi-Laptop Live Demo & LAN Attacks** | What happens when hosted on Laptop A and attacked from Laptop B, network routing, real IP extraction, and firewall configuration. |

---

## 2. Master Comparison Cheat Sheet: Tier 1 vs Tier 2 vs Tier 0/3

| Architectural Dimension | Layer 0 (Quarantine) | Layer 1 (Tier 1: Suricata) | Layer 2 (Tier 2: Machine Learning) | Layer 3 (Entropy & Decoys) |
| :--- | :--- | :--- | :--- | :--- |
| **Detection Paradigm** | Stateful In-Memory Hash Cache | Deterministic Deep Packet Inspection | Statistical Flow Anomaly Classification | Information Entropy & Decoy Route Traps |
| **Input Data Examined** | Source IP Address string | Raw L7 application-layer payload bytes & headers | 19 canonical statistical flow metrics vector | Byte frequency distribution & requested URL paths |
| **Processing Latency** | **~0.01 ms** (Sub-millisecond) | ~1.2 - 5.0 ms | **~27.27 microseconds** | ~0.05 - 0.15 ms |
| **Rule / Model Source** | Auto-enrolled on prior attacks | `suricata/rules/local.rules` (ET Open) | `models/rf_model.json` (Balanced Random Forest) | Shannon formula $H(X) \ge 4.85$, `HONEYPOT_PATHS` |
| **Primary Threats Caught** | Repeat attacking IPs, active brute force | Known CVEs: SQLi, Log4j JNDI, Nmap scans, SSH brute force | Zero-day volumetric floods, TCP SYN floods, Slowloris starvation | Obfuscated / XOR shellcode, polymorphic webshells, credential probing |
| **Blind Spots / Limitations** | Ineffective on first-time/new IPs | Blind to zero-days, encrypted streams, volumetric floods | Vulnerable to low-and-slow evasion (IAT stretching), base-rate fallacy | High false alarms if benign data is naturally compressed/encrypted |
| **Default Action When Matched** | Immediate HTTP 403 Pre-Filter Drop | Generates Signature Alert with Priority 1-4 | Generates ML Alert if $P(\text{malicious}) \ge 0.64$ | Flags high-entropy obfuscation or honeypot probe |

---

## 3. Hands-On Verification Guide

You can reproduce and observe every single layer described in these documents using the built-in commands:

### A. Run Automated Unit & Pipeline Tests
```powershell
# Python pipeline test suite (validates extractor, risk formula, campaign correlation)
python -m unittest backend\tests\test_pipeline.py -v

# TypeScript pipeline test suite (validates Express, SQLite, Suricata & ML engines)
npx --yes tsx --test src\lib\pipeline.test.ts
```

### B. Verify the 3 Core Sample Scenarios (A, B, C)
```powershell
# Scenario A (Known Attacks -> Suricata Signature Matches)
# Extracts 5 flows, fires 4 Suricata alerts (SQLi, Log4j, Nmap, SSH) -> Risk 80+
python -c "from backend.app.main import process_pcap_bytes_pipeline; print(process_pcap_bytes_pipeline('attack_signature.pcap', open('samples/attack_signature.pcap', 'rb').read()))"

# Scenario B (Unmatched Suspicious -> Machine Learning Fallback)
# 0 signature matches -> RF ML classifies volumetric flood -> Risk 70+
python -c "from backend.app.main import process_pcap_bytes_pipeline; print(process_pcap_bytes_pipeline('suspicious_unmatched_ml.pcap', open('samples/suspicious_unmatched_ml.pcap', 'rb').read()))"

# Scenario C (Normal Benign Traffic -> 0 Alerts)
# Normal HTTP/DNS -> 0 signature matches, ML prob < 0.25 -> 0 alerts created
python -c "from backend.app.main import process_pcap_bytes_pipeline; print(process_pcap_bytes_pipeline('benign_traffic.pcap', open('samples/benign_traffic.pcap', 'rb').read()))"
```

### C. Run the Multi-Layer Active Defense Simulation
```powershell
# Terminal 1: Start Server
npm run dev

# Terminal 2: Run 16 live traffic queries in Monitor Mode (IDS)
python live_demo.py --url http://localhost:3000

# Terminal 2: Run 16 live traffic queries in Active Prevention Mode (IPS with Auto-Quarantine)
python live_demo.py --url http://localhost:3000 --set-block on
```

### D. View the Interactive Standalone Visualizer
Open `visualizer/index.html` in Google Chrome, Microsoft Edge, or any modern web browser.
* Press `B` on your keyboard to toggle between Monitor Mode (IDS) and Active Prevention Mode (IPS).
* Press `P` to trigger Auto-Play presentation mode and watch packets animate through Layer 0, Layer 1, Layer 2, and Layer 3.
