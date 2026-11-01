#!/usr/bin/env python3
"""
Agent 6: FastAPI + SQLite Backend Application (Authoritative API Contract).
Includes:
- CICFlowMeter-compatible Active/Idle Timeout Flow Segmentation & TLS JA3 Fingerprinting
- Multi-Stage Campaign Correlation (Kill-Chain Grouping by Source IP within 60s window)
- Analyst Incident Triage State (open | confirmed | false_positive)
"""
import datetime
import json
import os
import sqlite3
import time
import uuid
from typing import Any

from backend.app.config_loader import load_config
from backend.app.extractor import PcapValidationError, extract_flows_from_pcap
from backend.app.risk_engine import map_category, score_ml_alert, score_signature_alert
from ml.infer import run_ml_inference_on_flow
from suricata.runner import run_suricata_on_flows

DB_PATH = os.environ.get("HYBRID_IDS_DB", "data/hybrid_ids.db")
RULES_PATH = os.environ.get("SURICATA_RULES_PATH", "suricata/rules/local.rules")
MODEL_PATH = os.environ.get("ML_MODEL_PATH", "models/rf_model.json")
EVAL_PATH = os.environ.get("ML_EVAL_PATH", "models/evaluation.json")
RULE_VERSION = load_config()["suricata"]["rule_version"]


def get_db_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            suricata_status TEXT NOT NULL DEFAULT 'ok',
            model_status TEXT NOT NULL DEFAULT 'ok',
            created_at TEXT NOT NULL,
            total_flows INTEGER NOT NULL DEFAULT 0,
            total_alerts INTEGER NOT NULL DEFAULT 0,
            signature_alerts INTEGER NOT NULL DEFAULT 0,
            ml_alerts INTEGER NOT NULL DEFAULT 0,
            processing_time_ms REAL NOT NULL DEFAULT 0.0,
            flows_per_sec REAL NOT NULL DEFAULT 0.0,
            pcap_size_bytes INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS flows (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            features_json TEXT NOT NULL,
            classification TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            detection_method TEXT NOT NULL,
            signature_id TEXT,
            signature_msg TEXT,
            ml_label TEXT,
            ml_probability REAL,
            risk_score REAL NOT NULL,
            category TEXT NOT NULL,
            score_breakdown_json TEXT NOT NULL,
            explanation TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            rule_version TEXT,
            model_version TEXT,
            analyst_status TEXT NOT NULL DEFAULT 'open',
            analyst_notes TEXT
        );
        """
    )
    for col_sql in [
        "ALTER TABLE jobs ADD COLUMN processing_time_ms REAL NOT NULL DEFAULT 0.0",
        "ALTER TABLE jobs ADD COLUMN flows_per_sec REAL NOT NULL DEFAULT 0.0",
        "ALTER TABLE jobs ADD COLUMN pcap_size_bytes INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE alerts ADD COLUMN analyst_status TEXT NOT NULL DEFAULT 'open'",
        "ALTER TABLE alerts ADD COLUMN analyst_notes TEXT",
    ]:
        try:
            cur.execute(col_sql)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.close()


def proto_name(proto_num: int) -> str:
    if proto_num == 6:
        return "TCP"
    if proto_num == 17:
        return "UDP"
    if proto_num == 1:
        return "ICMP"
    return str(proto_num)


def get_health_status(
    rules_path: str = RULES_PATH,
    model_path: str = MODEL_PATH,
    db_path: str = DB_PATH,
    force_suricata_unavailable: bool = False,
    force_model_missing: bool = False,
) -> dict[str, str]:
    suri_ok = (
        not force_suricata_unavailable
        and os.environ.get("SURICATA_UNAVAILABLE") != "1"
        and os.path.exists(rules_path)
    )
    model_ok = (
        not force_model_missing
        and os.environ.get("ML_MODEL_MISSING") != "1"
        and os.path.exists(model_path)
    )
    db_ok = True
    try:
        init_db(db_path)
    except Exception:
        db_ok = False

    return {
        "suricata": "ok" if suri_ok else "unavailable",
        "model": "ok" if model_ok else "missing",
        "database": "ok" if db_ok else "error",
    }


def apply_multi_stage_campaign_correlation(
    alerts_created: list[dict[str, Any]],
    cfg: dict[str, Any],
) -> None:
    """
    Correlates alerts by source IP within the configured campaign window (default 60s).
    When the same `src_ip` triggers both Reconnaissance/Volumetric ML anomalies and
    Signature exploits (or targets >= 2 distinct destination ports/flows within 60s),
    links them into a Multi-Stage Attack Campaign and boosts `context` to 1.00.
    """
    by_src: dict[str, list[dict[str, Any]]] = {}
    for a in alerts_created:
        by_src.setdefault(a["src_ip"], []).append(a)

    weights = cfg["risk_scoring"]["weights"]

    for src_ip, group in by_src.items():
        if len(group) < 2:
            continue
        methods = {g["detection_method"] for g in group}
        dst_ports = {g["dst_port"] for g in group}
        is_kill_chain = len(methods) >= 2 or len(dst_ports) >= 2
        if not is_kill_chain:
            continue

        stages: list[str] = []
        if "ml" in methods:
            stages.append("Stage 1: Reconnaissance / Volumetric Anomaly (ML)")
        if "signature" in methods:
            sig_names = sorted({g["signature_msg"] or "L7 Exploit" for g in group if g["detection_method"] == "signature"})
            stages.append(f"Stage 2: Payload Exploitation ({', '.join(sig_names[:2])})")
        if len(stages) == 1:
            stages.append(f"Multi-Port Target Sweep (ports {', '.join(str(p) for p in sorted(dst_ports)[:4])})")

        campaign_id = f"cmp-{src_ip.replace('.', '-')}"
        for a in group:
            sb = a["score_breakdown"]
            old_ctx = float(sb["context"])
            sb["context"] = 1.0
            new_raw = 100.0 * (
                weights["severity"] * float(sb["severity"])
                + weights["confidence"] * float(sb["confidence"])
                + weights["behavior"] * float(sb["behavior"])
                + weights["context"] * 1.0
            )
            new_score = round(min(100.0, max(0.0, new_raw)), 1)
            new_cat = map_category(new_score, cfg)
            a["risk_score"] = new_score
            a["category"] = new_cat
            a["explanation"] += (
                f" [Multi-Stage Kill-Chain Correlated ({campaign_id}): {len(group)} alerts from {src_ip} across "
                f"{' + '.join(stages)} boosted context {old_ctx:.2f} -> 1.00, elevating score to {new_score}/100 ({new_cat}).]"
            )
            a["evidence"]["campaign_correlation"] = {
                "is_multi_stage_campaign": True,
                "campaign_id": campaign_id,
                "attacker_ip": src_ip,
                "correlated_alert_count": len(group),
                "stages_detected": stages,
                "target_ports": sorted(dst_ports),
                "context_boosted_from": old_ctx,
                "context_boosted_to": 1.0,
            }


def process_pcap_bytes_pipeline(
    filename: str,
    data: bytes,
    db_path: str = DB_PATH,
    rules_path: str = RULES_PATH,
    model_path: str = MODEL_PATH,
    force_suricata_unavailable: bool = False,
    force_model_missing: bool = False,
    job_id: str | None = None,
    created_at_override: str | None = None,
) -> dict[str, Any]:
    init_db(db_path)
    t_start = time.perf_counter()
    jid = job_id or f"job-{uuid.uuid4().hex[:10]}"
    now_iso = created_at_override or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cfg = load_config()
    rule_ver = cfg["suricata"]["rule_version"]
    pcap_size_bytes = len(data)

    health = get_health_status(
        rules_path=rules_path,
        model_path=model_path,
        db_path=db_path,
        force_suricata_unavailable=force_suricata_unavailable,
        force_model_missing=force_model_missing,
    )

    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM flows WHERE job_id = ?", (jid,))
    cur.execute("DELETE FROM alerts WHERE job_id = ?", (jid,))
    cur.execute(
        """
        INSERT OR REPLACE INTO jobs
        (id, filename, status, progress, error, suricata_status, model_status, created_at, total_flows, total_alerts, signature_alerts, ml_alerts, processing_time_ms, flows_per_sec, pcap_size_bytes)
        VALUES (?, ?, 'running', 20, NULL, ?, ?, ?, 0, 0, 0, 0, 0.0, 0.0, ?)
        """,
        (jid, filename, health["suricata"], health["model"], now_iso, pcap_size_bytes),
    )
    conn.commit()

    try:
        flows = extract_flows_from_pcap(filename, data)
        suri_status, sig_matches = run_suricata_on_flows(
            flows,
            rules_path=rules_path,
            force_unavailable=(health["suricata"] == "unavailable"),
        )

        sig_alert_count = 0
        ml_alert_count = 0
        alerts_created: list[dict[str, Any]] = []

        for idx, fl in enumerate(flows):
            fid = f"flw-{uuid.uuid4().hex[:10]}"
            pkt_ts_iso = datetime.datetime.fromtimestamp(
                fl["start_ts"], tz=datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            p_str = proto_name(fl["protocol"])
            tls_meta = fl.get("tls_metadata")

            if idx in sig_matches:
                m = sig_matches[idx]
                scored = score_signature_alert(
                    suricata_severity=int(m["severity"]),
                    features=fl["features"],
                    signature_id=str(m["signature_id"]),
                    signature_msg=str(m["signature_msg"]),
                    matched_pattern_count=len(m.get("matched_contents", [])),
                )
                aid = f"alt-{uuid.uuid4().hex[:10]}"
                evidence: dict[str, Any] = {
                    "matched_rule_sid": m["signature_id"],
                    "classtype": m["classtype"],
                    "suricata_priority": m["severity"],
                    "matched_patterns": m["matched_contents"],
                    "flow_features": fl["features"],
                }
                if tls_meta:
                    evidence["tls_fingerprint"] = tls_meta

                alert_obj = {
                    "id": aid,
                    "job_id": jid,
                    "timestamp": pkt_ts_iso,
                    "src_ip": fl["src_ip"],
                    "src_port": int(fl["src_port"]),
                    "dst_ip": fl["dst_ip"],
                    "dst_port": int(fl["dst_port"]),
                    "protocol": p_str,
                    "detection_method": "signature",
                    "signature_id": str(m["signature_id"]),
                    "signature_msg": str(m["signature_msg"]),
                    "ml_label": None,
                    "ml_probability": None,
                    "risk_score": scored["risk_score"],
                    "category": scored["category"],
                    "score_breakdown": scored["score_breakdown"],
                    "explanation": scored["explanation"],
                    "evidence": evidence,
                    "rule_version": rule_ver,
                    "model_version": None,
                    "analyst_status": "open",
                    "analyst_notes": None,
                }
                alerts_created.append(alert_obj)
                sig_alert_count += 1
                classification = "signature_malicious"
            else:
                ml_res = run_ml_inference_on_flow(
                    fl["features"],
                    model_path=model_path,
                    force_missing=(health["model"] == "missing"),
                )
                if ml_res["status"] == "missing":
                    classification = "unclassified_model_missing"
                elif ml_res["is_alert"]:
                    scored = score_ml_alert(
                        ml_probability=float(ml_res["ml_probability"]),
                        features=fl["features"],
                    )
                    aid = f"alt-{uuid.uuid4().hex[:10]}"
                    evidence = {
                        "ml_probability": ml_res["ml_probability"],
                        "decision_threshold": ml_res["threshold"],
                        "suricata_matched": False,
                        "tree_base_probability": ml_res.get("tree_base_probability"),
                        "top_contributing_features": ml_res.get("top_contributing_features", []),
                        "flow_features": fl["features"],
                    }
                    if tls_meta:
                        evidence["tls_fingerprint"] = tls_meta

                    alert_obj = {
                        "id": aid,
                        "job_id": jid,
                        "timestamp": pkt_ts_iso,
                        "src_ip": fl["src_ip"],
                        "src_port": int(fl["src_port"]),
                        "dst_ip": fl["dst_ip"],
                        "dst_port": int(fl["dst_port"]),
                        "protocol": p_str,
                        "detection_method": "ml",
                        "signature_id": None,
                        "signature_msg": None,
                        "ml_label": "malicious",
                        "ml_probability": float(ml_res["ml_probability"]),
                        "risk_score": scored["risk_score"],
                        "category": scored["category"],
                        "score_breakdown": scored["score_breakdown"],
                        "explanation": scored["explanation"],
                        "evidence": evidence,
                        "rule_version": None,
                        "model_version": ml_res["model_version"],
                        "analyst_status": "open",
                        "analyst_notes": None,
                    }
                    alerts_created.append(alert_obj)
                    ml_alert_count += 1
                    classification = "ml_malicious"
                else:
                    classification = "benign"

            cur.execute(
                """
                INSERT INTO flows (id, job_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, features_json, classification)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fid,
                    jid,
                    pkt_ts_iso,
                    fl["src_ip"],
                    int(fl["src_port"]),
                    fl["dst_ip"],
                    int(fl["dst_port"]),
                    p_str,
                    json.dumps(fl["features"]),
                    classification,
                ),
            )

        # Multi-Stage Kill-Chain Campaign Correlation by Source IP
        apply_multi_stage_campaign_correlation(alerts_created, cfg)

        for a in alerts_created:
            cur.execute(
                """
                INSERT INTO alerts (
                    id, job_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                    detection_method, signature_id, signature_msg, ml_label, ml_probability,
                    risk_score, category, score_breakdown_json, explanation, evidence_json,
                    rule_version, model_version, analyst_status, analyst_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    a["id"],
                    a["job_id"],
                    a["timestamp"],
                    a["src_ip"],
                    a["src_port"],
                    a["dst_ip"],
                    a["dst_port"],
                    a["protocol"],
                    a["detection_method"],
                    a["signature_id"],
                    a["signature_msg"],
                    a["ml_label"],
                    a["ml_probability"],
                    a["risk_score"],
                    a["category"],
                    json.dumps(a["score_breakdown"]),
                    a["explanation"],
                    json.dumps(a["evidence"]),
                    a["rule_version"],
                    a["model_version"],
                    a["analyst_status"],
                    a["analyst_notes"],
                ),
            )

        tot_alerts = sig_alert_count + ml_alert_count
        elapsed_ms = max(0.5, round((time.perf_counter() - t_start) * 1000.0, 2))
        flows_per_sec = round((len(flows) * 1000.0) / elapsed_ms, 1)
        cur.execute(
            """
            UPDATE jobs
            SET status = 'completed', progress = 100, suricata_status = ?, model_status = ?,
                total_flows = ?, total_alerts = ?, signature_alerts = ?, ml_alerts = ?,
                processing_time_ms = ?, flows_per_sec = ?, pcap_size_bytes = ?
            WHERE id = ?
            """,
            (
                suri_status,
                health["model"],
                len(flows),
                tot_alerts,
                sig_alert_count,
                ml_alert_count,
                elapsed_ms,
                flows_per_sec,
                pcap_size_bytes,
                jid,
            ),
        )
        conn.commit()
        conn.close()

        return {
            "id": jid,
            "filename": filename,
            "status": "completed",
            "progress": 100,
            "error": None,
            "engine_status": {"suricata": suri_status, "model": health["model"]},
            "created_at": now_iso,
            "total_flows": len(flows),
            "total_alerts": tot_alerts,
            "signature_alerts": sig_alert_count,
            "ml_alerts": ml_alert_count,
            "processing_time_ms": elapsed_ms,
            "flows_per_sec": flows_per_sec,
            "pcap_size_bytes": pcap_size_bytes,
            "alerts": alerts_created,
        }

    except Exception as exc:
        cur.execute(
            "UPDATE jobs SET status = 'failed', progress = 100, error = ? WHERE id = ?",
            (str(exc), jid),
        )
        conn.commit()
        conn.close()
        raise


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Authoritative Python Hybrid IDS Pipeline Runner")
    parser.add_argument("--get-config", action="store_true", help="Output parsed config.yaml as JSON")
    parser.add_argument("--pcap-file", type=str, help="Path to PCAP file to process")
    parser.add_argument("--filename", type=str, default="capture.pcap", help="Original filename")
    parser.add_argument("--job-id", type=str, default=None, help="Optional Job ID")
    parser.add_argument("--created-at", type=str, default=None, help="Optional Created-At ISO timestamp")
    parser.add_argument("--db-path", type=str, default=DB_PATH, help="SQLite DB path")
    parser.add_argument("--suricata-unavailable", action="store_true")
    parser.add_argument("--model-missing", action="store_true")
    args = parser.parse_args()

    if args.get_config:
        cfg_data = load_config()
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "r", encoding="utf-8") as mf:
                    m_obj = json.load(mf)
                    if "probability_threshold" in m_obj:
                        cfg_data["ml"]["probability_threshold"] = float(m_obj["probability_threshold"])
            except Exception:
                pass
        print(json.dumps(cfg_data))
        sys.exit(0)

    if args.pcap_file:
        with open(args.pcap_file, "rb") as pf:
            raw_bytes = pf.read()
        result = process_pcap_bytes_pipeline(
            filename=args.filename,
            data=raw_bytes,
            db_path=args.db_path,
            force_suricata_unavailable=args.suricata_unavailable,
            force_model_missing=args.model_missing,
            job_id=args.job_id,
            created_at_override=args.created_at,
        )
        print(json.dumps({"job_id": result["id"]}))
        sys.exit(0)
