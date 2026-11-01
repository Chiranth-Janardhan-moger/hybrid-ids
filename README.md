# Hybrid Network Intrusion Detection System (Hybrid IDS)

A working end-to-end **Hybrid Network Intrusion Detection System** combining **Suricata Signature-Based Detection**, **Machine Learning Flow Classification (Random Forest)**, and **Risk-Based Threat Prioritization**.

---

## 1. Repository Structure

```text
├── ARCHITECTURE.md            # Architecture specification, agent ownership & task ledger
├── config.yaml                # Shared contract: risk formula weights, thresholds, paths
├── docker-compose.yml         # Offline PCAP Suricata container (jasonish/suricata)
├── server.ts                  # Full-stack Express + SQLite + Vite server (port 3000)
├── live_demo.py               # Live multi-layer traffic simulation runner
├── visualizer/
│   ├── index.html             # Standalone 4-tier IPS firewall visualizer
│   └── ips_firewall_visualizer.html
├── backend/
│   ├── requirements.txt       # Pinned Python 3.11 dependencies (FastAPI, Scapy, Scikit-learn)
│   ├── app/
│   │   ├── main.py            # FastAPI backend & SQLite pipeline
│   │   ├── extractor.py       # Bidirectional 5-tuple PCAP/PCAPNG 19-feature extractor
│   │   └── risk_engine.py     # Risk scoring formula & explanation generator
│   └── tests/
│       └── test_pipeline.py   # Automated Python test suite (unittest / pytest)
├── suricata/
│   ├── rules/local.rules      # ET Open compatible signature ruleset
│   └── runner.py              # Suricata runner, eve.json parser & 5-tuple/time-window correlator
├── ml/
│   ├── preprocess.py          # CICIDS2017 column mapper, Inf/NaN cleaner, deduplicator
│   ├── train.py               # Temporal day-based split trainer & held-out evaluator
│   └── infer.py               # Unmatched flow inference with missing-model safeguard
├── models/
│   ├── feature_schema.json    # Canonical 19-feature contract shared by extractor & ML
│   ├── rf_model.json          # Trained balanced Random Forest ensemble
│   └── evaluation.json        # Held-out test metrics & confusion matrix
├── samples/
│   ├── generate_samples.py    # Deterministic PCAP binary generator
│   ├── attack_signature.pcap  # Scenario A: SQLi, Log4j JNDI, Nmap, SSH Brute Force
│   ├── suspicious_unmatched_ml.pcap # Scenario B: Unmatched volumetric flood -> ML alert
│   └── benign_traffic.pcap    # Scenario C: Normal HTTP, HTTPS, and DNS traffic
├── data/                      # CICIDS2017 MachineLearningCVE CSVs + SQLite database
└── src/                       # React + TypeScript + Tailwind CSS + Recharts frontend
```

---

## 2. Windows Setup & Run Instructions (PowerShell)

### Prerequisites
- **Windows 10/11** with PowerShell
- **Python 3.11+** (`python --version`)
- **Node.js 20+** and **npm** (`node --version`, `npm --version`)
- **Docker Desktop** (for running `jasonish/suricata` container)

### Step 1: Python Virtual Environment & Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
```

### Step 2: Generate Sample PCAPs & Train / Evaluate the ML Model
Place CICIDS2017 CSV files in `.\data\` (if not present, `ml/train.py` automatically generates multi-day CICIDS2017-schema CSVs for Monday, Wednesday, and Friday):
```powershell
python samples\generate_samples.py
python ml\train.py
```

### Step 3: Run Automated Backend & Pipeline Tests
```powershell
python -m unittest backend\tests\test_pipeline.py -v
npx --yes tsx --test src\lib\pipeline.test.ts
```

### Step 4: Start the Application
You can run the unified full-stack server on port 3000:
```powershell
npm install
npm run dev
```
Or run FastAPI on port 8000 and Vite on port 3000 separately:
```powershell
# Terminal 1 (FastAPI Backend on http://localhost:8000, OpenAPI docs at http://localhost:8000/docs)
uvicorn backend.app.main:app --reload --port 8000

# Terminal 2 (Frontend + API Server on http://localhost:3000)
npm run dev
```

### Step 5: Optional Suricata Docker Offline PCAP Invocation
```powershell
docker compose run --rm suricata
```

### Step 6: Interactive 4-Tier IPS Firewall Visualizer
- **Live Online Visualizer**: [https://chiranth-janardhan-moger.github.io/hybrid-ids/](https://chiranth-janardhan-moger.github.io/hybrid-ids/)
- **Local File**: Open `visualizer/index.html` (or `visualizer/ips_firewall_visualizer.html`) directly in any web browser to run the standalone 4-layer defense walkthrough with Auto-Play presentation mode, live SVG packet animations, and keyboard shortcuts (`P` for Auto-Play, `B` for Block Mode, `F` for Fullscreen).

### Step 7: Multi-Layer Live Attack Mitigation Simulation
```powershell
# Monitor Mode: Run 16 scenarios with Block Mode OFF (IDS logs alerts, 0 blocked)
python live_demo.py --url http://localhost:3000

# Active Mitigation Mode: Run 16 scenarios with Block Mode ON (Drops attacks, quarantines attacker IPs)
python live_demo.py --url http://localhost:3000 --set-block on
```

---

## 3. Detection Pipeline & Risk Scoring Contract

```text
score = 100 * (0.40*severity + 0.30*confidence + 0.20*behavior + 0.10*context)
```
- **Signature Path**: Triggered when a flow correlates with a Suricata signature alert by bidirectional 5-tuple and time window (`5.0s`). `severity` maps from Suricata priority (`1 -> 1.00`, `2 -> 0.66`, `3 -> 0.33`), `confidence = 0.90` default.
- **ML Path**: Executed **only** on flows with no signature match. Predicts binary `benign` (`0`) vs `malicious` (`1`) using the 19 canonical flow features. Creates an alert **only** if `ml_probability >= 0.70` (`severity = 0.60`, `confidence = ml_probability`). Benign predictions create no alert while storing the flow.
- **Categories**: `Low` (< 30), `Medium` (30–59), `High` (60–79), `Critical` (>= 80).

---

## 4. Verification of Required Demo Scenarios (A–F)

| Scenario | Input / Action | Expected & Verified Outcome |
| :--- | :--- | :--- |
| **Scenario A (Known Attack)** | `samples/attack_signature.pcap` | 5 flows extracted; 4 match Suricata rules (`SID 2010935` SQLi, `SID 2034647` Log4j JNDI, `SID 2024364` Nmap, `SID 2001219` SSH scan) -> 4 signature alerts created with Critical/High risk scores. |
| **Scenario B (Unmatched Suspicious -> ML)** | `samples/suspicious_unmatched_ml.pcap` | 3 flows extracted (2 volumetric TCP floods + 1 benign HTTPS flow); 0 signature matches -> sent to ML inference -> 2 malicious ML alerts (`p >= 0.70`) created with High risk scores; benign flow creates no alert. |
| **Scenario C (Benign Traffic)** | `samples/benign_traffic.pcap` | 3 normal HTTP/DNS/HTTPS flows extracted -> 0 signature matches, all ML probabilities `< 0.25` -> **0 alerts** created, all 3 flows stored. |
| **Scenario D (Missing Dependencies)** | Toggle **Simulate Suricata Unavailable** or **Simulate ML Model Missing** on `/upload` | Health dot turns red; job records `engine_status.suricata = "unavailable"` or `engine_status.model = "missing"` and displays prominent red warning banners (`"Signature engine unavailable. Results may be incomplete."` / `"ML model missing. Unmatched traffic was not classified."`). Traffic is never silently passed as clean. |
| **Scenario E (Held-Out Evaluation)** | Open `/evaluation` (`GET /api/evaluation`) | Displays temporal day-split evaluation (`Train: Monday + Wednesday`, `Test: Friday`), 6 metrics (`Precision: 1.0000`, `Recall: 0.9190`, `F1: 0.9578`, `ROC-AUC: 0.9868`, `FPR: 0.0000`, `Accuracy: 0.9702`), and 2x2 confusion matrix (`[[720, 0], [34, 386]]`). |
| **Scenario F (Full Integration)** | End-to-end UI + API + SQLite + Export | Upload -> polling progress -> dashboard charts -> URL-synced alert filters -> alert detail drawer -> CSV/JSON export all verified. |

---

## 5. Known Limitations & Engineering Honesty

1. **No Zero-Day Guarantee**: Anomaly/ML classification on flow statistics cannot guarantee detection of novel or low-and-slow zero-day attacks that mimic normal flow timing and packet sizes.
2. **CICIDS2017 Dataset Quirks**: CICIDS2017 contains known flow termination artifacts and labeling noise; metrics on held-out Friday traffic do not guarantee equivalent performance on external production networks.
3. **19-Feature Subset**: Rather than using CICFlowMeter's 80+ features (many of which cannot be reproduced identically outside Java CICFlowMeter), both training and runtime inference are strictly constrained to the 19 canonical features in `models/feature_schema.json`.
4. **Runtime Distribution Shift**: The ML classifier is trained on labeled flows from Monday and Wednesday, whereas at runtime it evaluates only flows that did **not** match a Suricata signature.
5. **Hybrid Comparison on CSVs (`hybrid_comparison: null`)**: Because CICIDS2017 CSV files contain pre-aggregated flow statistics without raw L7 packet payloads, Suricata signature rules cannot be executed directly on the CSV test rows. Therefore `hybrid_comparison` in `models/evaluation.json` is set to `null` and documented transparently.
6. **Offline PCAP Scope**: This system processes uploaded `.pcap`/`.pcapng` captures (up to 100 MB) in offline mode; live NIC packet capture is out of scope.
