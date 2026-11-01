#!/usr/bin/env python3
"""
Agent 4: ML Inference Engine with Exact Additive Tree-Path Feature Attribution (Saabas / TreeSHAP).
Loads models/rf_model.json, models/feature_schema.json, and config.yaml.
Computes exact decision-path feature contributions across all trees in the Random Forest:
  base_prob + sum(tree_path_contribution_i) == predicted_probability
Also reports each feature's anomaly z-score relative to the benign training baseline.
"""
import json
import os
from typing import Any

from backend.app.config_loader import load_config
from ml.train import explain_forest_tree_path, predict_forest_proba


def compute_top_contributing_features(
    features: dict[str, Any],
    model: dict[str, Any],
    top_k: int = 4,
) -> list[dict[str, Any]]:
    feature_names: list[str] = model.get("feature_names", [])
    vec = [float(features.get(fname, 0.0)) for fname in feature_names]
    importances_list = model.get("feature_importances", [])
    imp_map = {item["feature"]: float(item["importance"]) for item in importances_list}
    stats_map = model.get("feature_stats", {})

    base_prob, path_contribs = explain_forest_tree_path(model.get("trees", []), vec, feature_names)

    attributions: list[dict[str, Any]] = []
    for idx, fname in enumerate(feature_names):
        val = vec[idx]
        imp = imp_map.get(fname, 0.01)
        st = stats_map.get(fname, {"benign_mean": 0.0, "benign_std": 1.0})
        b_mean = float(st.get("benign_mean", 0.0))
        b_std = max(float(st.get("benign_std", 1.0)), 1e-3)
        z_score = abs(val - b_mean) / b_std
        tree_delta = float(path_contribs[idx])
        attributions.append({
            "feature": fname,
            "value": round(val, 2),
            "benign_mean": round(b_mean, 2),
            "z_score": round(z_score, 2),
            "importance": round(imp, 4),
            "tree_prob_delta": round(tree_delta, 4),
            "base_prob": base_prob,
            "contribution": round(max(0.0, tree_delta), 4),
        })

    # Sort by positive tree-path probability contribution (how much this feature pushed P(malicious) up)
    attributions.sort(key=lambda x: (x["tree_prob_delta"], x["z_score"]), reverse=True)
    top_items = attributions[:top_k]
    total_pos = max(sum(max(0.0001, x["tree_prob_delta"]) for x in top_items), 1e-6)
    for item in top_items:
        item["share_pct"] = round((max(0.0001, item["tree_prob_delta"]) / total_pos) * 100.0, 1)
    return top_items


def run_ml_inference_on_flow(
    features: dict[str, Any],
    model_path: str = "models/rf_model.json",
    schema_path: str = "models/feature_schema.json",
    force_missing: bool = False,
) -> dict[str, Any]:
    cfg = load_config()
    cfg_threshold = float(cfg["ml"]["probability_threshold"])

    if force_missing or os.environ.get("ML_MODEL_MISSING") == "1" or not os.path.exists(model_path):
        return {
            "status": "missing",
            "ml_label": "unclassified",
            "ml_probability": None,
            "is_alert": False,
            "model_version": None,
            "threshold": cfg_threshold,
            "top_contributing_features": [],
        }

    with open(schema_path, "r", encoding="utf-8") as sf:
        schema = json.load(sf)
    with open(model_path, "r", encoding="utf-8") as mf:
        model = json.load(mf)

    vec = [float(features.get(f["name"], 0.0)) for f in schema["features"]]
    prob = round(predict_forest_proba(model["trees"], vec), 4)
    threshold = float(model.get("probability_threshold", cfg_threshold))
    is_malicious = prob >= threshold
    top_features = compute_top_contributing_features(features, model, top_k=4) if is_malicious else []

    return {
        "status": "ok",
        "ml_label": "malicious" if is_malicious else "benign",
        "ml_probability": prob,
        "is_alert": is_malicious,
        "model_version": model.get("model_version", cfg["ml"]["model_version"]),
        "threshold": threshold,
        "top_contributing_features": top_features,
    }
