# Architectural Synthesis: How & Why It Is Hybrid
## The Cascading Defense Paradigm & The Base-Rate Fallacy

This document explains the technical core of the system: **why the detection architecture is hybrid, how the cascading logic executes, and the mathematical justification for combining signatures with machine learning.**

---

## 1. Defining "Hybrid" in Modern Intrusion Detection

A detection system is not "hybrid" merely because it includes both a Python script and a rules file. In this architecture, **Hybrid** refers to a **formally coupled, cascading inspection cascade**:

1. **First Stage (Deterministic Filter):** Evaluates payload contents against deterministic signature rules (Suricata ET Open).
2. **Second Stage (Statistical Fallback):** Evaluates **only** those flows that passed through Stage 1 without a signature match against a calibrated Random Forest classifier.
3. **Third Stage (Risk Harmonization):** Normalizes the heterogeneous outputs (signature alerts vs statistical probability distributions) into a unified $[0, 100]$ operational threat score with multi-stage kill-chain correlation.

---

## 2. Why Neither Engine Can Survive Alone

To understand why a hybrid system is necessary, one must examine why standalone systems consistently fail in real-world Security Operations Centers (SOCs).

### Failure Mode 1: Signature-Only Systems
* **The Blind Spot:** Signatures require an attacker to use a known payload pattern. If an attacker:
  * Executes a TCP SYN or UDP amplification flood,
  * Throttles connections using Slowloris header delays, or
  * Employs a zero-day exploit with polymorphic byte encoding,
* **Result:** No signature matches. Suricata emits zero alerts. The attack breaches the network unimpeded.
* **Empirical Benchmark:** On our controlled 124-flow multi-class benchmark, Signature-Only detection achieved only **56.25% recall**, completely missing all volumetric and behavioral attacks.

### Failure Mode 2: Machine Learning-Only Systems & The Base-Rate Fallacy
Machine learning papers frequently claim "99% accuracy" on benchmark datasets. When deployed in enterprise networks, however, ML-only systems routinely fail due to **The Base-Rate Fallacy** (formulated by Axelsson and Sommer & Paxson).

#### The Mathematical Proof:
Let:
* $\text{TPR} = P(\hat{y}=1 \mid y=1) = 0.8762$ (Recall = 87.6%)
* $\text{FPR} = P(\hat{y}=1 \mid y=0) = 0.0292$ (False Positive Rate = 2.92%)
* $\pi = P(y=1)$ (The operational base-rate / prevalence of attacks on the network)

Using Bayes' theorem, the operational Positive Predictive Value (PPV or real-world Precision) is:
$$\text{PPV}(\pi) = \frac{\text{TPR} \cdot \pi}{\text{TPR} \cdot \pi + \text{FPR} \cdot (1 - \pi)}$$

#### Case A: Laboratory Benchmark ($\pi = 36.8\%$)
In academic datasets like CICIDS2017, attacks are artificially concentrated (e.g., 36.8% of flows are malicious):
$$\text{PPV}(0.368) = \frac{0.8762 \times 0.368}{(0.8762 \times 0.368) + (0.0292 \times 0.632)} = \frac{0.3224}{0.3224 + 0.0185} = \mathbf{94.6\%}$$
The model appears outstanding.

#### Case B: Production Enterprise Network ($\pi = 1.0\%$)
In a real enterprise network, genuine attacks represent approximately $1.0\%$ of network traffic ($\pi = 0.01$):
$$\text{PPV}(0.01) = \frac{0.8762 \times 0.01}{(0.8762 \times 0.01) + (0.0292 \times 0.99)} = \frac{0.00876}{0.00876 + 0.02891} = \mathbf{23.3\%}$$

**The Collapse:** At a realistic 1% base rate, the Positive Predictive Value collapses from **94.6% down to 23.3%**. More than 3 out of every 4 alerts are false positives. If the network processes 1,000,000 flows per day, the ML engine generates **28,908 false alerts every 24 hours**, completely overwhelming security analysts.

---

## 3. How the Hybrid Cascade Solves Both Problems

The hybrid architecture resolves both dilemmas by executing a **strictly ordered pipeline**:

```text
Incoming Flow
      |
      v
[ Suricata Signature Check ]
      |
      +---> [MATCHED?]
               |
              YES ---> Known-Threat Path:
               |       - Severity derived from Suricata Priority (1.00, 0.68, 0.36)
               |       - Base Confidence = 0.90
               |       - Generates Signature Alert immediately
               |       - ML INFERENCE IS SKIPPED FOR THIS FLOW
               |
              NO ----> Unmatched Flow Path:
                       |
                       v
             [ Random Forest ML Inference ]
                       |
                       +---> [ P(malicious) >= 0.64 ? ]
                                |
                               YES ---> Volumetric / Zero-Day ML Alert
                                |       - Severity derived from flow intensity
                                |       - Confidence = P(malicious)
                                |
                               NO ----> Benign Flow (Stored, 0 Alert)
```

### Why Skipping ML on Matched Flows is Crucial:
1. **CPU Efficiency:** Suricata matches are resolved quickly. Skipping the 19-feature ML tree traversal on already-identified threats saves compute cycles for unmatched traffic.
2. **False Negative Prevention:** If an attacker sends a genuine SQL injection payload inside a very low-rate, normal-looking flow (e.g., a single HTTP GET), the ML flow classifier might rate it as "benign" because the packet timing is normal. Because Suricata catches it first, the attacker cannot hide behind benign flow statistics.
3. **Protection Against Base-Rate Collapse:** ML is invoked only on the residual stream, and its alerts are prioritized by the 4-Factor Risk Engine rather than triggering blunt automated bans.

---

## 4. Empirical Benchmark Comparison

On a controlled 124-flow raw PCAP validation benchmark containing mixed multi-class traffic (SQLi, Log4j JNDI, Nmap port scans, SSH brute force, TCP SYN floods, Slowloris, and Benign HTTPS/DNS):

| Detection Paradigm | Total Attacks | Attacks Caught | Recall (TPR) | False Positives | Benchmark Conclusion |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Signature-Only (Suricata)** | 64 | 36 | **56.25%** | 0 | Missed all volumetric TCP floods and stealthy port scans without L7 signatures. |
| **ML-Only (Random Forest)** | 64 | 26 | **40.62%** | 3 | Missed single-packet low-rate SQLi and Log4j exploits whose flow statistics mimicked normal browsing. |
| **Proposed Hybrid Cascade** | 64 | 62 | **96.88%** | 0 | **Caught both classes.** 95% Wilson Confidence Interval: $[89.3\%, 99.1\%]$. |

The hybrid cascade increased attack recall from **56.25% to 96.88%** while maintaining zero false positives on verified benign traffic.

---

## 5. Graceful Degradation & Engine Health (Scenario D)

A critical principle of defensive engineering is: **A security system must never fail silently as "clean".**

If a dependency crashes (e.g., Docker daemon terminates or an ML model file is accidentally deleted), an incompetent IDS might report: *"0 threats detected — network is 100% clean!"* 

Our backend explicitly tracks and surfaces engine degradation states:

### State A: Suricata Unavailable
* **Trigger:** Docker is stopped, or `suricata/rules/local.rules` is deleted, or admin toggles `suricata_unavailable: true`.
* **System Response:**
  * Job status records `engine_status.suricata = "unavailable"`.
  * Frontend dashboard displays a prominent red warning banner:
    `"Signature engine unavailable. Results may be incomplete."`
  * The pipeline automatically routes **all** flows directly to the Random Forest ML classifier so volumetric and behavioral protection remains active.
  * Health indicator dot turns amber/red.

### State B: ML Model Missing
* **Trigger:** `models/rf_model.json` is missing or corrupted, or admin toggles `model_missing: true`.
* **System Response:**
  * Job status records `engine_status.model = "missing"`.
  * Frontend dashboard displays a prominent warning banner:
    `"ML model missing. Unmatched traffic was not classified."`
  * Unmatched flows are recorded in SQLite with classification `unclassified_model_missing`.
  * Suricata signature detection continues operating normally for known exploits.
  * Unmatched flows are flagged transparently as uninspected rather than passed as clean.

This guarantees operational integrity: SOC analysts are always aware when network visibility is degraded.
