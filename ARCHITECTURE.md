# Hybrid Network Intrusion Detection System — Architecture & Task Ledger

## 1. Environment Inspection Report

| Component | Target Windows Environment | Container Verification Environment | Status & Adaptation |
| :--- | :--- | :--- | :--- |
| **OS** | Windows 10/11 (PowerShell) | Linux 4.19.0-gvisor x86_64 | Windows PowerShell setup & run scripts provided in `README.md` |
| **Python** | Python 3.11 (`venv`, `pip`) | Python 3.10.12 (stdlib `sqlite3`, `csv`, `struct`, `json`, `math`, `unittest`) | Full `backend/` & `ml/` Python code provided + stdlib runner so training, tests, and PCAP synthesis run natively without external wheels |
| **Node / npm** | Node 20+, npm 10+ | Node v22.23.3 (`node:sqlite` enabled), npm 10.9.9 | Installed and verified |
| **Docker / Suricata** | Docker Desktop + `jasonish/suricata` | Docker daemon not present in gVisor sandbox | Suricata Docker wrapper (`suricata/runner.py`) invokes `docker run --rm jasonish/suricata` when available, with ET Open rule evaluator & explicit `unavailable` state toggle for Scenario D |
| **Disk Space** | >= 5 GB | 504 GB available | Verified |

---

## 2. Detection Pipeline Architecture

```
PCAP Upload (.pcap / .pcapng, max 100 MB)
   │
   ├─► 1. Validation & Bidirectional 5-Tuple Flow Extraction
   │      Computes 19 canonical flow features defined in models/feature_schema.json
   │
   ├─► 2. Suricata Signature Detection + 5-Tuple/Time-Window Correlation
   │      ├─► [MATCHED] ──► Known-Threat Path:
   │      │                 severity from Suricata (1->1.0, 2->0.66, 3->0.33),
   │      │                 confidence=0.90, behavior & context from flow features.
   │      │                 Creates signature alert.
   │      │
   │      └─► [UNMATCHED] ─► ML Inference Path (Random Forest on 19 features):
   │                        ├─► P(malicious) >= threshold (0.70):
   │                        │   severity=0.60, confidence=P(malicious),
   │                        │   behavior & context from flow features.
   │                        │   Creates ML alert.
   │                        └─► P(malicious) < threshold (0.70):
   │                            Classified benign -> No alert created (flow stored).
   │
   └─► 3. Degraded / Failure States (Never Fail Closed as "Clean")
          ├─► Suricata unavailable -> job.engine_status.suricata = "unavailable"
          └─► ML model missing     -> job.engine_status.model = "missing"
```

---

## 3. Agent Ownership & Non-Overlapping File Boundaries

| Agent ID | Role | Owned Files |
| :--- | :--- | :--- |
| **Agent 1** | Lead & Architecture | `ARCHITECTURE.md`, `config.yaml`, `models/feature_schema.json` |
| **Agent 2** | PCAP & Flow Extraction | `backend/app/extractor.py`, `src/lib/pcapExtractor.ts`, `samples/generate_samples.py` |
| **Agent 3** | Suricata Integration & Correlation | `suricata/rules/local.rules`, `suricata/runner.py`, `src/lib/suricataEngine.ts` |
| **Agent 4** | ML Training & Inference | `ml/preprocess.py`, `ml/train.py`, `ml/infer.py`, `src/lib/mlEngine.ts`, `data/*.csv`, `models/rf_model.json`, `models/evaluation.json` |
| **Agent 5** | Risk Engine & Alert Schema | `backend/app/risk_engine.py`, `src/lib/riskEngine.ts` |
| **Agent 6** | Backend (FastAPI + SQLite + Express Bridge) | `backend/app/main.py`, `backend/app/database.py`, `backend/requirements.txt`, `server.ts` |
| **Agent 7** | Frontend UI (React + TS + Tailwind + Recharts) | `src/types.ts`, `src/api.ts`, `src/components/*`, `src/pages/*`, `src/App.tsx` |
| **Agent 8** | QA, Automated Tests & Documentation | `backend/tests/test_pipeline.py`, `src/lib/pipeline.test.ts`, `README.md` |

---

## 4. Authoritative Task Ledger

| Task ID | Agent | Objective | Dependencies | Deliverables | Acceptance Criteria | Verification Method | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T-01** | Agent 1 | Architecture Spec & Shared Contracts | None | `ARCHITECTURE.md`, `config.yaml`, `models/feature_schema.json` | Exact 19 features, risk formula, and API schemas locked | File inspection | **VERIFIED** |
| **T-02** | Agent 2 | PCAP Validator, Flow Extractor & Sample PCAP Generator | T-01 | `backend/app/extractor.py`, `src/lib/pcapExtractor.ts`, `samples/*.pcap` | Parses `.pcap`/`.pcapng`, rejects >100MB/empty/corrupt, computes 19 features | Unit test & sample PCAP extraction | **VERIFIED** |
| **T-03** | Agent 3 | Suricata Runner, Ruleset & 5-Tuple Time-Window Correlator | T-01 | `suricata/rules/local.rules`, `suricata/runner.py`, `src/lib/suricataEngine.ts` | Matches known signatures, correlates by 5-tuple + window, surfaces `unavailable` state | Unit test & Scenario A/D | **VERIFIED** |
| **T-04** | Agent 4 | CICIDS2017 Day-Split Training, Evaluation & Inference | T-01 | `ml/train.py`, `ml/infer.py`, `models/rf_model.json`, `models/evaluation.json` | Day-based split (no random leakage), real precision/recall/F1/ROC-AUC/FPR/CM saved | Run `python3 ml/train.py` & verify JSON | **VERIFIED** |
| **T-05** | Agent 5 | Risk Scoring Engine & Explanation Generator | T-01 | `backend/app/risk_engine.py`, `src/lib/riskEngine.ts` | Exact `100*(0.4S+0.3C+0.2B+0.1X)` formula, Low/Medium/High/Critical thresholds | `unittest` & `node:test` | **VERIFIED** |
| **T-06** | Agent 6 | Backend API & SQLite Persistence | T-02..T-05 | `backend/app/main.py`, `server.ts`, `data/hybrid_ids.db` | All `/api/*` endpoints match exact JSON contract | `curl` & integration test | **VERIFIED** |
| **T-07** | Agent 7 | Clean Light-Theme React Frontend | T-01, T-06 | `src/types.ts`, `src/api.ts`, `src/pages/*`, `src/components/*` | `npm run build` passes, zero mock data, clean light UI | `compile_applet` & Playwright | **VERIFIED** |
| **T-08** | Agent 8 | Scenarios A-F Verification, Unit Tests & Windows README | T-06, T-07 | `backend/tests/test_pipeline.py`, `src/lib/pipeline.test.ts`, `README.md` | Scenarios A-F run and documented honestly | Automated tests + Playwright | **VERIFIED** |
