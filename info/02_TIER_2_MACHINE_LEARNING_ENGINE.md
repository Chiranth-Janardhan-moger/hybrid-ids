# Tier 2 Defense: Machine Learning Anomaly Engine
## Balanced Random Forest & Explainable Flow Classification

This document provides a comprehensive technical study of **Tier 2** in the Hybrid IDPS pipeline: the **Machine Learning Flow Anomaly Detection Engine**.

---

## 1. What is Machine Learning Flow Detection?

While Tier 1 inspects packet payloads for specific known character strings, **Tier 2** inspects the **statistical behavior of network conversations** (flows). 

A flow is a sequence of packets traveling in both directions between two endpoints:
```text
(Source IP, Source Port, Destination IP, Destination Port, Protocol)
```

Tier 2 does not read payload bytes. Instead, it measures quantitative properties of the transmission:
* How many packets were sent forward vs backward?
* What was the mean inter-arrival time (time between consecutive packets)?
* What was the byte rate per second?
* What TCP control flags (SYN, FIN, RST, PSH, ACK) were set?

By analyzing these features with a trained supervised classifier, Tier 2 detects **behavioral anomalies** such as volumetric Denial-of-Service (DoS/DDoS) floods, port-scanning sweeps, brute-force connection floods, and zero-day traffic that has no known signature.

---

## 2. Why Balanced Random Forest?

Our machine learning engine implements a **Balanced Random Forest Classifier** (25 decision trees). 

### Why Random Forest over Deep Learning (DNN/LSTM/Transformers)?
1. **Ultra-Low Latency:** Inference latency is **27.27 microseconds per flow** (running pure tree evaluations). In contrast, deep neural networks require matrix multiplications and GPU/ONNX runtimes that typically introduce 1 to 10 milliseconds of latency per flow.
2. **Resistance to Tabular Overfitting:** Deep learning architectures often overfit on tabular network traffic features. Decision tree ensembles naturally handle mixed integer/float tabular distributions with varying scales.
3. **Exact Mathematical Explainability:** Unlike black-box neural networks, every tree path in a Random Forest can be decomposed exactly into individual feature probability deltas (Saabas / TreeSHAP formulation).
4. **Class Imbalance Mitigation:** Network traffic is inherently imbalanced (99% benign, 1% attack). Balanced bagging draws bootstrap samples with balanced class distributions, preventing majority-class collapse.

---

## 3. The 19 Canonical Flow Features

Rather than relying on proprietary or un-reproducible feature extractors (e.g., CICFlowMeter's 80+ features, many of which suffer from floating-point incompatibilities), Tier 2 strictly adheres to the 19 canonical features defined in `models/feature_schema.json`:

| Feature Name | Type | Unit / Range | Cybersecurity Role |
| :--- | :--- | :--- | :--- |
| `destination_port` | int | 0 - 65535 | Identifies target service (e.g., port 80 web, port 22 SSH) |
| `protocol` | int | 6 (TCP), 17 (UDP), 1 (ICMP) | Transport protocol |
| `flow_duration` | float | Microseconds ($\mu\text{s}$) | Duration of entire flow session |
| `total_fwd_packets` | int | Packets | Packets from source to destination |
| `total_bwd_packets` | int | Packets | Packets from destination back to source |
| `total_length_of_fwd_packets` | float | Bytes | Total forward payload and header volume |
| `total_length_of_bwd_packets` | float | Bytes | Total backward response volume |
| `min_packet_length` | float | Bytes | Minimum packet size seen in flow |
| `max_packet_length` | float | Bytes | Maximum packet size seen in flow |
| `packet_length_mean` | float | Bytes | Average packet size |
| `packet_length_std` | float | Bytes | Packet size variance (high for mixed traffic, zero for fixed floods) |
| `flow_bytes_s` | float | Bytes / second | Bandwidth consumption rate |
| `flow_packets_s` | float | Packets / second | Transmission speed (extreme in DoS floods) |
| `flow_iat_mean` | float | Microseconds ($\mu\text{s}$) | Average inter-arrival time between packets |
| `fin_flag_count` | int | Count | Normal TCP connection teardowns |
| `syn_flag_count` | int | Count | Connection establishment requests (abnormally high in SYN floods) |
| `rst_flag_count` | int | Count | Connection resets (high in scanners hitting closed ports) |
| `psh_flag_count` | int | Count | Push flags (high in active data pushes like shell sessions) |
| `ack_flag_count` | int | Count | Acknowledgments (low in spoofed or one-way flood attacks) |

---

## 4. Leak-Free Temporal Training Methodology

A critical failure in academic NIDS literature is **random k-fold cross-validation on the same day's traffic**. When packets from the same attack session are randomly shuffled between training and test sets, the model memorizes IP subnets and exact timestamps, reporting a synthetic 99.9% accuracy that collapses to zero on new traffic (data leakage).

### Our Temporal Split Protocol (CICIDS2017):
To ensure honest, production-grade generalization, the training pipeline in `ml/train.py` enforces a **strict temporal day-based split**:
* **Training Set:** Monday (Normal benign activity) + Wednesday (DoS Hulk and GoldenEye attacks). Total: 2,496 flows.
* **Held-Out Test Set:** Friday (Unseen DDoS Low Orbit Ion Cannon and Friday Afternoon PortScans). Total: 1,140 flows (720 benign, 420 attack).

The model is evaluated **strictly once** on the held-out Friday data without ever observing Friday traffic during training or hyperparameter tuning.

### Held-Out Evaluation Metrics:
* **Precision:** `0.9460` (94.6% of flagged flows were genuine attacks)
* **Recall (TPR):** `0.8762` (87.6% of unseen Friday DDoS attacks caught)
* **F1 Score:** `0.9098`
* **ROC-AUC:** `0.9733`
* **False Positive Rate (FPR):** `0.0292` (2.92%)
* **Inference Latency:** `27.27 microseconds / flow`

---

## 5. Operating Decision Threshold and Platt Calibration

The default decision threshold in most binary classifiers is $\tau = 0.50$. In network security, $\tau = 0.50$ is unacceptable because it generates excessive false alarms on noisy benign web browsing.

### Selection of $\tau^* = 0.64$:
During validation, the decision threshold $\tau^*$ was optimized to maximize the $F_{0.5}$ score (which weights precision twice as heavily as recall) while enforcing a strict constraint:
$$\text{FPR} \le 1.5\%$$
This yielded the production operating threshold:
$$\tau^* = 0.64$$

### Classification Decision Rule:
For any unmatched flow with feature vector $\mathbf{x} \in \mathbb{R}^{19}$:
* If $P(\text{malicious} \mid \mathbf{x}) \ge 0.64$: **Flagged as Malicious ML Alert**. Severity is assigned based on flow intensity and confidence equals $P(\text{malicious})$.
* If $P(\text{malicious} \mid \mathbf{x}) < 0.64$: **Classified as Benign**. The flow record is stored in the database for auditing, but no alert is emitted to the analyst.

---

## 6. Explainable AI (XAI): Exact Saabas Tree-Path Feature Attribution

A common objection to machine learning in cybersecurity is: *"The model says it is malicious, but it cannot tell me why."*

To eliminate black-box opacity, `ml/infer.py` implements **Exact Additive Tree-Path Decomposition (Saabas algorithm)** across all 25 trees in the forest.

### Mathematical Formulation:
At each internal node $t$ of a decision tree, the sample belongs to a region with an empirical probability $v(t) = P(y=1)$. When the sample tests feature $j$ and transitions to child node $c$, the decision step produces an incremental probability delta:
$$\Delta P_j = v(c) - v(t)$$

Summing these deltas along the actual traversal paths of all 25 trees produces an exact additive attribution:
$$P(\text{malicious}) = P_{\text{base}} + \sum_{i=1}^{19} \Delta P_i$$

Where:
* $P_{\text{base}}$ is the global base probability across the forest root nodes.
* $\Delta P_i$ is the exact probability contribution of feature $i$.

### Real SOC Output Example:
When an unmatched volumetric TCP flood is processed, Tier 2 produces:
```json
{
  "ml_probability": 0.964,
  "threshold": 0.64,
  "top_contributing_features": [
    {
      "feature": "flow_packets_s",
      "value": 14285.7,
      "benign_mean": 45.2,
      "z_score": 14.82,
      "tree_prob_delta": 0.3812,
      "share_pct": 47.8
    },
    {
      "feature": "syn_flag_count",
      "value": 120,
      "benign_mean": 1.1,
      "z_score": 11.24,
      "tree_prob_delta": 0.2450,
      "share_pct": 30.7
    },
    {
      "feature": "flow_iat_mean",
      "value": 70.0,
      "benign_mean": 22100.0,
      "z_score": 8.91,
      "tree_prob_delta": 0.1710,
      "share_pct": 21.5
    }
  ]
}
```
The analyst can immediately verify:
1. `flow_packets_s` is $14.82$ standard deviations above normal, contributing $+38.1\%$ to the threat probability.
2. `syn_flag_count` is $11.24$ standard deviations above normal, contributing $+24.5\%$.
3. The threat is an un-spoofed high-rate TCP SYN flood.

---

## 7. Strengths and Inherent Limitations of Tier 2

### Strengths:
1. **Zero-Signature Detection:** Catches novel DDoS attacks, botnet floods, and brute-force sweeps that carry zero signature payloads.
2. **Encrypted Channel Visibility:** Because features are computed from packet sizes, timings, and header flags, Tier 2 detects anomalies inside encrypted HTTPS/TLS tunnels without decrypting payloads.
3. **Sub-Millisecond Speed:** $27.27\,\mu\text{s}$ per flow allows processing tens of thousands of flows per second in software.

### Inherent Limitations:
1. **Adversarial Evasion:** If an attacker deliberately throttles their attack (Low-and-Slow attacks like Slowloris) or pads packet payloads with random bytes to mimic normal web distributions, statistical features blur and recall drops.
2. **The Base-Rate Fallacy:** If deployed alone on raw network traffic where attacks represent $< 0.1\%$ of flows, even a 2.9% FPR will trigger hundreds of false alarms daily.

**Conclusion:** Tier 2 must never operate in isolation. It functions optimally as a **fallback tier** evaluating traffic that has already passed through **Tier 1 (Suricata)**.
