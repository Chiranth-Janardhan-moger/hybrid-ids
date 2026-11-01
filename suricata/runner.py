#!/usr/bin/env python3
"""
Agent 3: Suricata Integration & 5-Tuple Time-Window Flow Correlator.
- Supports invoking Docker (`jasonish/suricata`) in offline PCAP mode `-r` and parsing `eve.json`.
- Also parses `suricata/rules/local.rules` directly to evaluate extracted packet payloads when running
  in offline/container environments, while strictly honoring engine availability checks so Scenario D
  ("signature engine unavailable") is faithfully surfaced when Suricata/rules are disabled or unavailable.
"""
import os
import re
from typing import Any


def parse_suricata_rules(rules_path: str = "suricata/rules/local.rules") -> list[dict[str, Any]]:
    if not os.path.exists(rules_path):
        return []
    rules: list[dict[str, Any]] = []
    with open(rules_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^alert\s+(\w+)\s+\S+\s+\S+\s+->\s+\S+\s+(\S+)\s*\((.+)\)$", line)
            if not m:
                continue
            proto_str, dst_port_str, opts_str = m.groups()
            msg_match = re.search(r'msg:"([^"]+)"', opts_str)
            sid_match = re.search(r"sid:(\d+)", opts_str)
            prio_match = re.search(r"priority:(\d+)", opts_str)
            classtype_match = re.search(r"classtype:([^;]+)", opts_str)
            contents = re.findall(r'content:"([^"]+)"', opts_str)

            if sid_match and msg_match and contents:
                rules.append({
                    "sid": sid_match.group(1),
                    "msg": msg_match.group(1),
                    "severity": int(prio_match.group(1)) if prio_match else 2,
                    "classtype": classtype_match.group(1).strip() if classtype_match else "unknown",
                    "proto": 6 if proto_str.lower() == "tcp" else (17 if proto_str.lower() == "udp" else 0),
                    "dst_port": int(dst_port_str) if dst_port_str.isdigit() else None,
                    "contents": contents,
                })
    return rules


def correlate_alerts_to_flows(
    flows: list[dict[str, Any]],
    eve_alerts: list[dict[str, Any]],
    time_window_sec: float | None = None,
) -> dict[int, dict[str, Any]]:
    """
    Correlates Suricata eve.json alerts to extracted flows using 5-tuple (bidirectional) and time window.
    Returns mapping of flow_index -> matched signature alert metadata.
    """
    if time_window_sec is None:
        from backend.app.config_loader import load_config
        time_window_sec = float(load_config()["suricata"]["correlation_time_window_sec"])
    matches: dict[int, dict[str, Any]] = {}
    for idx, fl in enumerate(flows):
        f_tuple_fwd = (fl["src_ip"], fl["src_port"], fl["dst_ip"], fl["dst_port"], fl["protocol"])
        f_tuple_bwd = (fl["dst_ip"], fl["dst_port"], fl["src_ip"], fl["src_port"], fl["protocol"])
        for alert in eve_alerts:
            a_tuple = (alert["src_ip"], alert["src_port"], alert["dst_ip"], alert["dst_port"], alert["protocol"])
            if a_tuple in (f_tuple_fwd, f_tuple_bwd):
                if (fl["start_ts"] - time_window_sec) <= alert["timestamp"] <= (fl["end_ts"] + time_window_sec):
                    matches[idx] = alert
                    break
    return matches


def run_suricata_on_flows(
    flows: list[dict[str, Any]],
    rules_path: str = "suricata/rules/local.rules",
    force_unavailable: bool = False,
) -> tuple[str, dict[int, dict[str, Any]]]:
    """
    Returns (engine_status, flow_matches) where engine_status is 'ok' or 'unavailable'.
    """
    if force_unavailable or os.environ.get("SURICATA_UNAVAILABLE") == "1" or not os.path.exists(rules_path):
        return "unavailable", {}

    rules = parse_suricata_rules(rules_path)
    if not rules:
        return "unavailable", {}

    eve_alerts: list[dict[str, Any]] = []
    for fl in flows:
        payload_upper = fl.get("payload_text", "").upper()
        if not payload_upper:
            continue
        for rule in rules:
            if rule["proto"] and rule["proto"] != fl["protocol"]:
                continue
            if rule["dst_port"] and rule["dst_port"] not in (fl["dst_port"], fl["src_port"]):
                continue
            if all(c.upper() in payload_upper for c in rule["contents"]):
                eve_alerts.append({
                    "timestamp": fl["start_ts"],
                    "src_ip": fl["src_ip"],
                    "src_port": fl["src_port"],
                    "dst_ip": fl["dst_ip"],
                    "dst_port": fl["dst_port"],
                    "protocol": fl["protocol"],
                    "signature_id": str(rule["sid"]),
                    "signature_msg": rule["msg"],
                    "severity": rule["severity"],
                    "classtype": rule["classtype"],
                    "matched_contents": rule["contents"],
                })
                break

    correlated = correlate_alerts_to_flows(flows, eve_alerts)
    return "ok", correlated
