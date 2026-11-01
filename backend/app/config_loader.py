#!/usr/bin/env python3
"""
Shared YAML Configuration Loader for Python Backend & ML Pipeline.
Parses config.yaml without requiring external packages if PyYAML is not installed.
"""
import os
from typing import Any


def load_config(config_path: str = "config.yaml") -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "app": {"max_upload_mb": 100, "database_path": "data/hybrid_ids.db"},
        "flow_timeouts": {
            "active_timeout_sec": 120.0,
            "idle_timeout_sec": 30.0,
            "campaign_correlation_window_sec": 60.0,
        },
        "suricata": {
            "rules_path": "suricata/rules/local.rules",
            "correlation_time_window_sec": 5.0,
            "rule_version": "ET-Open-2026.10-local-v1",
        },
        "ml": {
            "model_path": "models/rf_model.json",
            "feature_schema_path": "models/feature_schema.json",
            "evaluation_path": "models/evaluation.json",
            "model_version": "rf-cicids2017-v1.1",
            "probability_threshold": 0.64,
        },
        "risk_scoring": {
            "weights": {"severity": 0.40, "confidence": 0.30, "behavior": 0.20, "context": 0.10},
            "signature_defaults": {
                "severity_map": {1: 0.95, 2: 0.68, 3: 0.36, 4: 0.18},
                "base_confidence": 0.78,
            },
            "ml_defaults": {"base_severity": 0.58},
            "categories": {"low_max": 29, "medium_max": 59, "high_max": 79, "critical_min": 80},
        },
    }

    try:
        import yaml  # type: ignore
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    for k, v in loaded.items():
                        if isinstance(v, dict) and k in cfg and isinstance(cfg[k], dict):
                            cfg[k].update(v)
                        else:
                            cfg[k] = v
                    return cfg
    except ImportError:
        pass

    if not os.path.exists(config_path):
        return cfg

    with open(config_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            k, v = [x.strip().strip('"') for x in stripped.split(":", 1)]
            if not v:
                continue
            if k == "correlation_time_window_sec":
                cfg["suricata"]["correlation_time_window_sec"] = float(v)
            elif k == "active_timeout_sec":
                cfg["flow_timeouts"]["active_timeout_sec"] = float(v)
            elif k == "idle_timeout_sec":
                cfg["flow_timeouts"]["idle_timeout_sec"] = float(v)
            elif k == "campaign_correlation_window_sec":
                cfg["flow_timeouts"]["campaign_correlation_window_sec"] = float(v)
            elif k == "probability_threshold":
                cfg["ml"]["probability_threshold"] = float(v)
            elif k == "base_confidence":
                cfg["risk_scoring"]["signature_defaults"]["base_confidence"] = float(v)
            elif k == "base_severity":
                cfg["risk_scoring"]["ml_defaults"]["base_severity"] = float(v)
            elif k in ("severity", "confidence", "behavior", "context"):
                cfg["risk_scoring"]["weights"][k] = float(v)
            elif k in ("low_max", "medium_max", "high_max", "critical_min"):
                cfg["risk_scoring"]["categories"][k] = int(float(v))
    return cfg
