#!/usr/bin/env python3
"""
Agent 5: Authoritative Risk Scoring Engine (Analyst Triage & Prioritization Heuristic).
Single source of truth for alert risk scoring across the entire application.
All weights, category cutoffs, and base parameters are loaded from config.yaml via backend/app/config_loader.py.
- Framed explicitly as an operational analyst prioritization heuristic (0-100) combining:
    score = 100 * (w_sev * severity + w_conf * confidence + w_beh * behavior + w_ctx * context)
- Volumetric DoS/SYN floods elevate ML severity proportionally to flow rate/flag intensity so high-rate
  floods reach High/Critical urgency while borderline low-rate anomalies remain Medium.
"""
from typing import Any
from backend.app.config_loader import load_config

PRIVILEGED_OR_SENSITIVE_PORTS = {21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443}


def compute_behavior_score(features: dict[str, Any]) -> float:
    pkt_rate = float(features.get("flow_packets_s", 0.0))
    byte_rate = float(features.get("flow_bytes_s", 0.0))
    syn_cnt = float(features.get("syn_flag_count", 0))
    rst_cnt = float(features.get("rst_flag_count", 0))
    psh_cnt = float(features.get("psh_flag_count", 0))
    fwd_pkts = max(1.0, float(features.get("total_fwd_packets", 1)))
    bwd_pkts = float(features.get("total_bwd_packets", 0))
    pkt_std = float(features.get("packet_length_std", 0.0))

    rate_factor = min(1.0, pkt_rate / 1200.0) * 0.42 + min(1.0, byte_rate / 800_000.0) * 0.28
    flag_factor = min(1.0, (syn_cnt + rst_cnt + psh_cnt * 0.5) / 20.0) * 0.18
    asymmetry_factor = (1.0 - min(1.0, bwd_pkts / fwd_pkts)) * 0.07
    variance_factor = min(1.0, pkt_std / 350.0) * 0.05

    return round(min(1.0, max(0.06, rate_factor + flag_factor + asymmetry_factor + variance_factor)), 4)


def compute_context_score(dst_port: int, protocol: int, features: dict[str, Any] | None = None) -> float:
    if dst_port in (22, 3389, 445, 1433, 3306, 5432):
        score = 0.86
    elif dst_port in (80, 443, 8080, 8443):
        score = 0.74
    elif dst_port in PRIVILEGED_OR_SENSITIVE_PORTS or (0 < dst_port < 1024):
        score = 0.58
    else:
        score = 0.32

    if protocol == 6:
        score += 0.05
    if features:
        fwd_bytes = float(features.get("total_length_of_fwd_packets", 0.0))
        if fwd_bytes > 500:
            score += min(0.08, fwd_bytes / 25000.0)
    return round(min(1.0, score), 4)


def compute_signature_confidence(
    base_confidence: float,
    matched_patterns_count: int,
    dst_port: int,
    features: dict[str, Any],
) -> float:
    pattern_bonus = min(0.12, max(0, matched_patterns_count - 1) * 0.06)
    port_bonus = 0.04 if dst_port in PRIVILEGED_OR_SENSITIVE_PORTS else 0.01
    bwd_bonus = 0.03 if int(features.get("total_bwd_packets", 0)) > 0 else 0.0
    return round(min(0.98, max(0.50, base_confidence + pattern_bonus + port_bonus + bwd_bonus)), 4)


def map_category(risk_score: float, cfg: dict[str, Any] | None = None) -> str:
    c = (cfg or load_config())["risk_scoring"]["categories"]
    if risk_score >= c["critical_min"]:
        return "Critical"
    if risk_score >= (c["medium_max"] + 1):
        return "High"
    if risk_score >= (c["low_max"] + 1):
        return "Medium"
    return "Low"


def score_signature_alert(
    suricata_severity: int,
    features: dict[str, Any],
    signature_id: str,
    signature_msg: str,
    matched_patterns_count: int = 1,
    matched_pattern_count: int | None = None,
    confidence: float | None = None,
) -> dict[str, Any]:
    if matched_pattern_count is not None:
        matched_patterns_count = matched_pattern_count
    cfg = load_config()
    rs_cfg = cfg["risk_scoring"]
    weights = rs_cfg["weights"]
    sev_map = rs_cfg["signature_defaults"]["severity_map"]
    base_conf = float(rs_cfg["signature_defaults"]["base_confidence"])

    severity = float(sev_map.get(suricata_severity, sev_map.get(str(suricata_severity), 0.36)))
    dst_port = int(features.get("destination_port", 0))
    proto = int(features.get("protocol", 6))

    conf = (
        round(float(confidence), 4)
        if confidence is not None
        else compute_signature_confidence(base_conf, matched_patterns_count, dst_port, features)
    )
    behavior = compute_behavior_score(features)
    context = compute_context_score(dst_port, proto, features)

    raw_score = 100.0 * (
        weights["severity"] * severity
        + weights["confidence"] * conf
        + weights["behavior"] * behavior
        + weights["context"] * context
    )
    final_score = round(min(100.0, max(0.0, raw_score)), 1)
    category = map_category(final_score, cfg)

    explanation = (
        f"Analyst prioritization heuristic: Matched Suricata rule [{signature_id}] '{signature_msg}' "
        f"(priority {suricata_severity} -> severity={severity:.2f}, rule specificity confidence={conf:.2f} "
        f"from {matched_patterns_count} content pattern(s)). Flow behavior={behavior:.2f} and port {dst_port} "
        f"context={context:.2f} yielded {final_score}/100 ({category})."
    )

    return {
        "risk_score": final_score,
        "category": category,
        "score_breakdown": {
            "severity": severity,
            "confidence": conf,
            "behavior": behavior,
            "context": context,
            "weights": dict(weights),
        },
        "explanation": explanation,
    }


def score_ml_alert(
    ml_probability: float,
    features: dict[str, Any],
    severity: float | None = None,
) -> dict[str, Any]:
    cfg = load_config()
    rs_cfg = cfg["risk_scoring"]
    weights = rs_cfg["weights"]
    threshold = float(cfg["ml"]["probability_threshold"])
    base_sev = float(rs_cfg["ml_defaults"]["base_severity"])

    dst_port = int(features.get("destination_port", 0))
    proto = int(features.get("protocol", 6))
    behavior = compute_behavior_score(features)
    context = compute_context_score(dst_port, proto, features)

    # Volumetric DoS/SYN floods (high behavior score) elevate heuristic severity up to 0.88 so floods reach High/Critical,
    # while low-rate borderline anomalies remain around base_severity (0.58) and score Medium.
    computed_sev = round(min(0.88, base_sev + behavior * 0.28), 4) if severity is None else round(float(severity), 4)
    confidence = round(float(ml_probability), 4)

    raw_score = 100.0 * (
        weights["severity"] * computed_sev
        + weights["confidence"] * confidence
        + weights["behavior"] * behavior
        + weights["context"] * context
    )
    final_score = round(min(100.0, max(0.0, raw_score)), 1)
    category = map_category(final_score, cfg)

    explanation = (
        f"Analyst prioritization heuristic: Unmatched flow classified malicious by Random Forest "
        f"(p={confidence:.2f} >= τ*={threshold:.2f}). Volumetric-adjusted severity={computed_sev:.2f}, "
        f"confidence={confidence:.2f}, behavior={behavior:.2f} ({features.get('flow_packets_s', 0):.1f} pkts/s), "
        f"and port {dst_port} context={context:.2f} yielded {final_score}/100 ({category})."
    )

    return {
        "risk_score": final_score,
        "category": category,
        "score_breakdown": {
            "severity": computed_sev,
            "confidence": confidence,
            "behavior": behavior,
            "context": context,
            "weights": dict(weights),
        },
        "explanation": explanation,
    }
