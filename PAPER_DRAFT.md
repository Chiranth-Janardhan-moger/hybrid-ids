# Calibrated Hybrid Network Intrusion Detection and Active Prevention via Cascading Signature Inspection, Tree-Path Explainable Machine Learning, and Base-Rate Aware Risk Prioritization

**Target Venue:** IEEE / Springer International Conference on Network Security & Machine Learning  
**Artifact Repository:** Reproducible Python (FastAPI/Scapy) + Suricata + React/TypeScript SOC Platform (`config.yaml`, `ml/train.py`, `live_demo.py`)

---

## Abstract
Machine Learning-based Network Intrusion Detection Systems (ML-NIDS) frequently report near-perfect accuracy on benchmark datasets such as CICIDS2017 yet fail in production Security Operations Centers (SOCs) due to three systemic flaws: **(1) Train-Serve Feature Skew** between offline CSV flow generators and live packet extractors, **(2) The Base-Rate Fallacy**, where a $2.92\%$ False Positive Rate (FPR) yields $94.6\%$ precision at a $36.8\%$ laboratory attack prevalence but collapses to $23.3\%$ precision at a realistic $1.0\%$ enterprise attack base rate, and **(3) Vulnerability to Temporal Slow-and-Low Evasion**. In this paper, we design and implement a **Calibrated Hybrid Intrusion Detection and Prevention System (Hybrid IDPS)** that unifies deep-packet Suricata signature matching, unencrypted TLS `ClientHello` (JA3/SNI) fingerprinting, and a Platt-calibrated Balanced Random Forest operating over a strict 19-feature packet-to-flow contract (`active_timeout=120s`, `idle_timeout=30s`). To mitigate SOC alert fatigue under low base rates, we introduce a **4-Factor Risk Prioritization Engine** augmented with **Exact Per-Alert Tree-Path Feature Attribution ($\Delta P$)** and **Multi-Stage Kill-Chain Campaign Correlation**. Evaluated under a leak-free temporal split (training on Monday/Wednesday DoS Hulk traffic and testing on unseen Friday DDoS traffic, $N=1,140$), our Balanced Random Forest achieves an F1-score of $0.9098$, ROC-AUC of $0.9733$, and $27.27\,\mu\text{s/flow}$ inference latency while reducing false positives by $>2.4\times$ compared to single-tree and linear baselines. On a controlled 124-flow multi-class raw PCAP benchmark, the hybrid cascade improves recall from $56.25\%$ (Signature-only) and $40.62\%$ (ML-only) to **$96.88\%$ ($95\%$ Wilson CI $[89.3\%, 99.1\%]$)** and enforces real-time inline HTTP 403 blocking against active attacks while preserving $100\%$ of benign user traffic.

**Index Terms—** Network Intrusion Detection System (NIDS), Intrusion Prevention System (IPS), Suricata, Random Forest, Base-Rate Fallacy, Platt Calibration, Adversarial Evasion, Explainable AI (XAI), JA3 Fingerprinting.

---

## I. Introduction & Core Research Contributions

Modern enterprise networks face both known application-layer exploits (e.g., SQL Injection, Apache Log4j JNDI Remote Code Execution) and zero-signature volumetric or slow-rate anomalies. While signature engines such as Suricata achieve near-zero false positives on known L7 payloads, they are blind to zero-day volumetric floods and encrypted TLS channels. Conversely, standalone Machine Learning (ML) flow classifiers suffer from high false-alarm fatigue when deployed at realistic network base rates ($\pi \le 1\%$).

### Key Contributions of This Work
1. **Elimination of Train-Serve Feature Skew:** We define an authoritative 19-feature bidirectional flow schema (`models/feature_schema.json`) computed identically by our raw PCAP packet extractor (`backend/app/extractor.py`) and offline training pipeline (`ml/train.py`), enforcing `CICFlowMeter`-compatible active ($120\text{s}$) and idle ($30\text{s}$) flow segmentation.
2. **Leak-Free Validation & Probability Calibration:** Rather than tuning decision thresholds on the held-out test set, we select the operating threshold $\tau^* = 0.64$ by maximizing $F_{0.5}$ subject to $\text{FPR} \le 1.5\%$ on a $20\%$ Monday+Wednesday validation split, and fit Platt logistic scaling to calibrate raw tree-vote fractions.
3. **Exact Tree-Path Explainability ($\Delta P$) & Multi-Stage Kill-Chain Correlation:** For every ML alert, we decompose the prediction along the 25 decision trees using Saabas additive node-value deltas ($\Delta P$), and automatically correlate multi-stage reconnaissance-to-exploitation sequences from the same source IP within a $60\text{s}$ sliding window.
4. **Adversarial Evasion & Concept Drift Quantification:** We systematically evaluate classifier resilience against byte padding ($+20\%, +50\%$) and temporal inter-arrival time (IAT) stretching ($2\times, 5\times$), and monitor feature distribution shift via the Population Stability Index (PSI).

---

## II. Related Work & Comparative Literature Gap Analysis

To justify the architectural necessity of our Calibrated Hybrid IDPS, Table 0 cross-verifies our framework against five foundational and contemporary classes of Intrusion Detection literature across eight critical deployment dimensions:

### Table 0: Cross-Verification Against Existing NIDS Literature & Identified Research Gaps

| Reference / Existing Approach | Detection Paradigm | Train-Serve Skew Mitigation | Temporal / Unseen Attack Split | Base-Rate Fallacy & Calibration | Explainability (XAI) | Adversarial Evasion Testing | Encrypted TLS (JA3) & Active IPS | Key Limitation / Research Gap Addressed by Our Work |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Sharafaldin et al. (2018)** [1] (*CICIDS2017 Benchmark*) | Offline ML (RF, ID3, Adaboost on CSV flows) | ❌ Offline CSV only (no live packet extractor) | ❌ Random $k$-fold split on same-day attacks | ❌ Reports raw precision at $\sim 30\%$ attack rate | ❌ Global Gini importance only | ❌ None | ❌ None | **Gap 1:** Models trained on pre-computed CSVs fail on live PCAPs due to flow-timeout and feature-extractor skew. |
| **Sommer & Paxson (2010)** [2] & **Axelsson (2000)** [3] | Foundational ML-NIDS & Base-Rate Analysis | ⚠️ Conceptual critique | ⚠️ Conceptual critique | ✅ Formulates Bayes PPV collapse at low $\pi$ | ❌ None | ❌ None | ❌ None | **Gap 2:** Identifies why ML-NIDS fail in SOCs (alert fatigue & lack of operational context) but provides no hybrid risk-scoring + XAI implementation. |
| **Conventional Hybrid NIDS** (e.g., *Suricata + Uncalibrated RF/DNN*) [4], [5] | Signature + ML Cascade | ❌ Separate offline CSV vs. live Zeek/Suricata logs | ❌ Same-distribution train/test split | ❌ Uncalibrated tree votes; fixed $\tau=0.50$ | ❌ Black-box probability or global SHAP | ❌ Rarely evaluated | ❌ Blind to TLS or passive IDS only | **Gap 3:** Uncalibrated RF votes cluster away from $\{0,1\}$; fixed $\tau=0.50$ causes high FPR; lacks per-alert tree-path $\Delta P$ and inline HTTP 403 blocking. |
| **Apruzzese et al. (2022)** [6] (*Adversarial ML-NIDS*) | ML Flow Classifiers under Evasion | ❌ Offline flow perturbation only | ⚠️ Partial | ❌ Ignores base-rate PPV | ❌ None | ✅ Evaluates byte padding & IAT delay | ❌ Passive ML only | **Gap 4:** Shows that $5\times$ IAT stretching degrades flow-ML recall, but does not integrate L7 Suricata signatures + $30\text{s}/120\text{s}$ timeouts to catch throttled payloads. |
| **Proposed Calibrated Hybrid IDPS (This Work)** | **Suricata L7 + JA3 TLS + Platt-Calibrated Balanced RF** | **✅ Shared 19-Feature Contract (`120s/30s` timeouts)** | **✅ Train Mon/Wed (Hulk) $\to$ Test Fri (Unseen DDoS)** | **✅ Validation $\tau^*=0.64$, Platt Scaling & Bayes PPV** | **✅ Exact Per-Alert Tree-Path $\Delta P$ (Saabas)** | **✅ $+20\%/+50\%$ Padding & $2\times/5\times$ IAT Stress Test** | **✅ Unencrypted TLS `ClientHello` JA3 + Inline 403 IPS** | **Closes Gaps 1–4:** End-to-end reproducible PCAP-to-IPS pipeline with $96.88\%$ hybrid recall, $27.27\,\mu\text{s}$ latency, and PSI drift monitoring. |

---

## III. System Architecture & Mathematical Formulation

### A. Cascading Hybrid Detection Pipeline
Given a raw packet capture (PCAP) or live network stream, packets are grouped into bidirectional 5-tuple flows $f = (\text{src\_ip}, \text{src\_port}, \text{dst\_ip}, \text{dst\_port}, \text{proto})$ segmented at $T_{\text{idle}} = 30\text{s}$ and $T_{\text{active}} = 120\text{s}$.
1. **Stage 1 (Signature & JA3 Inspection):** Each flow is inspected against Suricata rules (`suricata/rules/local.rules`) within a $\pm 5.0\text{s}$ correlation window. Simultaneously, unencrypted TCP port 443 payloads starting with TLS record byte `0x16` (`ClientHello`) are parsed to extract the TLS version, Server Name Indication (SNI), cipher suite list, and MD5 **JA3 fingerprint** without decrypting payload data.
2. **Stage 2 (Calibrated ML Fallback):** Flows with no signature match are mapped to $\mathbf{x} \in \mathbb{R}^{19}$ and evaluated by the Balanced Random Forest. An alert is raised if and only if $P(\text{malicious} \mid \mathbf{x}) \ge \tau^* = 0.64$.

### B. Bayes-Adjusted Precision Under the Base-Rate Fallacy
Let $\text{TPR} = P(\hat{y}=1 \mid y=1)$ and $\text{FPR} = P(\hat{y}=1 \mid y=0)$. At an operational network attack prevalence $\pi = P(y=1)$, the Positive Predictive Value (Precision) is governed by Bayes' theorem:
$$\text{PPV}(\pi) = \frac{\text{TPR} \cdot \pi}{\text{TPR} \cdot \pi + \text{FPR} \cdot (1 - \pi)}$$
Because $\text{PPV}(\pi)$ degrades sharply as $\pi \to 0.001$, automated blocking on raw ML detections is unsafe without multi-factor risk prioritization.

### C. Four-Factor Risk Prioritization & Kill-Chain Context Boost
Every alert (Signature or ML) is mapped into a unified $[0, 100]$ triage score:
$$\text{RiskScore} = \text{round}\Big(100 \times \big(0.40 \cdot S_{\text{sev}} + 0.30 \cdot S_{\text{conf}} + 0.20 \cdot S_{\text{beh}} + 0.10 \cdot S_{\text{ctx}}\big), 1\Big)$$
When the same source IP triggers alerts across distinct kill-chain stages (e.g., Stage 1 ML Port/SYN Recon on port 443 followed by Stage 2 Suricata Log4j Exploit on port 8080 within $60\text{s}$), the campaign correlator links the alerts under a shared `campaign_id` and elevates $S_{\text{ctx}} \to 1.00$.

---

## IV. Experimental Results

### Table I: Multi-Model Classifier & Inference Latency Comparison (Held-Out Friday Test Set, $N=1,140$)
All models were trained strictly on Monday+Wednesday flows ($2,496$ flows including disjoint extractor calibration) and evaluated once on held-out Friday unseen DDoS + Benign flows ($1,140$ flows: $420$ attack, $720$ benign).

| Classifier Architecture | Threshold ($\tau$) | Precision | Recall (TPR) | F1 Score | FPR | ROC-AUC | Latency ($\mu\text{s/flow}$) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Balanced Random Forest (Proposed)** | **0.64** | **0.9460** | **0.8762** | **0.9098** | **0.0292** | **0.9733** | **27.27 $\mu\text{s}$** |
| Single Decision Tree (CART $d=4$) | 0.60 | 0.8846 | 0.9310 | 0.9072 | 0.0708 | 0.9537 | 1.45 $\mu\text{s}$ |
| L2-Regularized Logistic Regression | 0.62 | 0.8803 | 0.9452 | 0.9116 | 0.0750 | 0.9713 | 3.74 $\mu\text{s}$ |
| Unsupervised Z-Score Outlier Detector | 0.58 | 0.9524 | 0.8095 | 0.8752 | 0.0236 | 0.9480 | 3.79 $\mu\text{s}$ |

*Key Finding:* Single decision trees and linear logistic regression suffer from $>2.4\times$ higher False Positive Rates ($7.08\%$ and $7.50\%$ vs. $2.92\%$), which would generate $>70$ false alarms per $1,000$ benign flows in production.

---

### Table II: Complementary Coverage Ablation on Controlled 124-Flow Raw PCAP Benchmark
Evaluated on 124 raw packet flows ($60$ benign, $64$ attack across 5 classes; seed=9001, strictly disjoint from training seed=101).

| Detection Mode | Precision (95% CI) | Recall (95% CI) | F1 Score | False Positives ($N=60$) |
| :--- | :---: | :---: | :---: | :---: |
| **Signature Only (Suricata)** | 1.0000 $[0.9036, 1.0000]$ | 0.5625 $[0.4409, 0.6771]$ | 0.7200 | 0 / 60 ($0.00\%$) |
| **ML Only (Random Forest)** | 0.9630 $[0.8172, 0.9934]$ | 0.4062 $[0.2946, 0.5285]$ | 0.5714 | 1 / 60 ($1.67\%$) |
| **Hybrid Cascade (Proposed)** | **0.9841** $[0.9154, 0.9972]$ | **0.9688** $[0.8930, 0.9914]$ | **0.9764** | **1 / 60 ($1.67\%$)** |

---

### Table III: Adversarial Evasion & Feature Perturbation Stress Test ($N=420$ Held-Out Attack Flows)
We perturb the 420 held-out Friday attack flows to simulate an adaptive adversary attempting to evade flow-level ML detection:

| Adversarial Scenario | Perturbation Applied | Detected / 420 | ML Recall (95% CI) | Mean $P(\text{mal})$ | Architectural Defense |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Unperturbed Baseline** | Original held-out Friday DDoS flows | 368 / 420 | **87.62%** $[84.1\%, 90.4\%]$ | 0.8617 | Baseline Random Forest ($\tau^*=0.64$) |
| **+20% Byte Padding** | Packet lengths $+20\%$, bytes/s $+20\%$ | 368 / 420 | **87.62%** $[84.1\%, 90.4\%]$ | 0.8620 | Flag & packet-count splits invariant to $+20\%$ padding |
| **+50% Padding + Jitter** | Packet lengths $+50\%$, std $\times 1.8$ | 368 / 420 | **87.62%** $[84.1\%, 90.4\%]$ | 0.8759 | High packet length reinforces volumetric flood trees |
| **2x IAT Slowdown** | Inter-arrival delay $\times 2$, rate $\times 0.5$ | 344 / 420 | **81.90%** $[77.9\%, 85.3\%]$ | 0.8140 | Moderate degradation on borderline probes |
| **5x IAT + SYN Throttling** | Duration $\times 5$, SYN flags $-50\%$ | 275 / 420 | **65.48%** $[60.8\%, 69.9\%]$ | 0.6551 | Mitigated by L7 Suricata rules & 30s/120s flow timeouts |

---

### Table IV: Base-Rate Fallacy & Bayes-Adjusted Precision Across Network Regimes
Using held-out $\text{TPR} = 0.8762$ and $\text{FPR} = 0.0292$ ($29.17$ false alarms per $1,000$ benign flows):

| Attack Base Rate ($\pi$) | Operational Network Scenario | Expected Precision $\text{PPV}(\pi)$ | Expected TP / 1k Flows | Expected FP / 1k Flows |
| :---: | :--- | :---: | :---: | :---: |
| **0.10%** | Enterprise Internal LAN Baseline | **2.92%** | 0.88 | 29.14 |
| **0.50%** | Perimeter / DMZ Traffic | **13.11%** | 4.38 | 29.02 |
| **1.00%** | High-Risk Subnet | **23.26%** | 8.76 | 28.88 |
| **5.00%** | Active Incident Window | **61.26%** | 43.81 | 27.71 |
| **36.84%** | Raw Benchmark Test Split | **94.60%** | 322.81 | 18.42 |

---

## V. Reproducibility & Live Verification Commands

1. **Retrain Models, Multi-Model Baselines, Platt Calibration & PSI Drift Analysis:**
   ```bash
   python3 ml/train.py
   ```
2. **Run End-to-End Unit & Integration Tests (Python + TypeScript):**
   ```bash
   python3 -m unittest backend/tests/test_pipeline.py -v
   npx tsx --test src/lib/pipeline.test.ts
   ```
3. **Run Live Terminal Traffic & Active IPS Prevention Proof:**
   ```bash
   # Pass 1: IPS Blocking OFF (All 4 Safe + 4 Attack queries return 200 ALLOWED; IDS raises alerts)
   python3 live_demo.py --set-block off

   # Pass 2: IPS Blocking ON (All 4 Safe queries return 200 ALLOWED; all 4 Attack queries return 403 BLOCKED)
   python3 live_demo.py --set-block on
   ```

---

## VI. References

1. I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," in *Proc. ICISSP*, 2018, pp. 108–116.
2. R. Sommer and V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection," in *Proc. IEEE Symposium on Security and Privacy (S&P)*, 2010, pp. 305–316.
3. S. Axelsson, "The Base-Rate Fallacy and the Difficulty of Intrusion Detection," *ACM Transactions on Information and System Security (TISSEC)*, vol. 3, no. 3, pp. 186–205, 2000.
4. K. Nam and K. Kim, "Hybrid Intrusion Detection System Combining Signature-Based and Anomaly-Based Detection," *IEEE Access*, 2021.
5. M. Ring, S. Wunderlich, D. Scheuring, D. Landes, and A. Hotho, "A Survey of Network-Based Intrusion Detection Data Sets," *Computers & Security*, vol. 86, pp. 147–167, 2019.
6. G. Apruzzese, M. Colajanni, L. Ferretti, A. Guido, and M. Marchetti, "Modeling Realistic Adversarial Attacks against Network Intrusion Detection Systems," *Digital Threats: Research and Practice*, vol. 3, no. 3, pp. 1–19, 2022.
7. J. Althouse, J. Atkinson, and J. Atkins, "TLS Fingerprinting with JA3 and JA3S," *Salesforce Engineering*, 2019.
8. J. Platt, "Probabilistic Outputs for Support Vector Machines and Comparisons to Regularized Likelihood Methods," *Advances in Large Margin Classifiers*, MIT Press, 1999.

