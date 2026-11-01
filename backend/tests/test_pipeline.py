#!/usr/bin/env python3
"""
Agent 8: Automated Python Test Suite (unittest + pytest compatible)
Verifies:
1. Feature schema compatibility between models/feature_schema.json and PCAP flow extractor
2. Risk scoring formula (100 * (0.4*S + 0.3*C + 0.2*B + 0.1*X)) and category boundaries
3. Suricata 5-tuple + time-window correlation
4. Scenario A: Known attack PCAP -> Signature alerts created with risk scores
5. Scenario B: Unmatched suspicious PCAP -> ML alerts created when probability >= threshold
6. Scenario C: Benign PCAP -> 0 alerts created, all flows stored
7. Scenario D: Missing Suricata / Missing ML model -> Explicit engine_status ('unavailable' / 'missing'), never clean
"""
import json
import os
import tempfile
import unittest

from backend.app.extractor import PcapValidationError, extract_flows_from_pcap
from backend.app.main import process_pcap_bytes_pipeline
from backend.app.risk_engine import map_category, score_ml_alert, score_signature_alert
from suricata.runner import correlate_alerts_to_flows


class TestHybridIDSPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()

    def tearDown(self) -> None:
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_01_feature_schema_compatibility(self) -> None:
        with open("models/feature_schema.json", "r", encoding="utf-8") as f:
            schema = json.load(f)
        expected_names = [feat["name"] for feat in schema["features"]]
        self.assertEqual(len(expected_names), 19)

        with open("samples/attack_signature.pcap", "rb") as pf:
            flows = extract_flows_from_pcap("attack_signature.pcap", pf.read())
        self.assertGreaterEqual(len(flows), 4)
        for fl in flows:
            self.assertEqual(list(fl["features"].keys()), expected_names)

    def test_02_risk_scoring_contract(self) -> None:
        sample_features = {
            "destination_port": 80,
            "protocol": 6,
            "flow_packets_s": 600.0,
            "flow_bytes_s": 400000.0,
            "syn_flag_count": 10,
            "rst_flag_count": 5,
            "psh_flag_count": 4,
        }
        sig_res = score_signature_alert(1, sample_features, "2010935", "SQL Injection")
        bd = sig_res["score_breakdown"]
        expected = round(100.0 * (0.4 * bd["severity"] + 0.3 * bd["confidence"] + 0.2 * bd["behavior"] + 0.1 * bd["context"]), 1)
        self.assertEqual(sig_res["risk_score"], expected)
        self.assertEqual(sig_res["category"], map_category(expected))
        self.assertEqual(map_category(29.9), "Low")
        self.assertEqual(map_category(30.0), "Medium")
        self.assertEqual(map_category(60.0), "High")
        self.assertEqual(map_category(80.0), "Critical")

        # Low-confidence ML prediction must NOT become Critical
        ml_low = score_ml_alert(0.71, {"destination_port": 8080, "protocol": 6, "flow_packets_s": 50.0, "flow_bytes_s": 5000.0})
        self.assertLess(ml_low["risk_score"], 80.0)

    def test_03_suricata_correlation_5tuple_and_window(self) -> None:
        flows = [
            {"src_ip": "192.168.1.10", "src_port": 50000, "dst_ip": "10.0.0.5", "dst_port": 80, "protocol": 6, "start_ts": 100.0, "end_ts": 102.0},
            {"src_ip": "192.168.1.11", "src_port": 50001, "dst_ip": "10.0.0.5", "dst_port": 443, "protocol": 6, "start_ts": 200.0, "end_ts": 201.0},
        ]
        eve_alerts = [
            {"src_ip": "192.168.1.10", "src_port": 50000, "dst_ip": "10.0.0.5", "dst_port": 80, "protocol": 6, "timestamp": 101.5, "signature_id": "2010935", "signature_msg": "SQLi", "severity": 1},
            # Out of time window alert for second flow
            {"src_ip": "192.168.1.11", "src_port": 50001, "dst_ip": "10.0.0.5", "dst_port": 443, "protocol": 6, "timestamp": 250.0, "signature_id": "2024364", "signature_msg": "Scan", "severity": 2},
        ]
        correlated = correlate_alerts_to_flows(flows, eve_alerts, time_window_sec=5.0)
        self.assertIn(0, correlated)
        self.assertNotIn(1, correlated)

    def test_04_scenario_a_known_attack_pcap(self) -> None:
        with open("samples/attack_signature.pcap", "rb") as f:
            res = process_pcap_bytes_pipeline("attack_signature.pcap", f.read(), db_path=self.temp_db.name)
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["engine_status"]["suricata"], "ok")
        self.assertGreaterEqual(res["signature_alerts"], 4)
        self.assertEqual(res["ml_alerts"], 0)

    def test_05_scenario_b_unmatched_suspicious_ml_pcap(self) -> None:
        from backend.app.config_loader import load_config
        cfg_thresh = float(load_config()["ml"]["probability_threshold"])
        with open("samples/suspicious_unmatched_ml.pcap", "rb") as f:
            res = process_pcap_bytes_pipeline("suspicious_unmatched_ml.pcap", f.read(), db_path=self.temp_db.name)
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["signature_alerts"], 0)
        self.assertGreaterEqual(res["ml_alerts"], 2)
        for alert in res["alerts"]:
            self.assertEqual(alert["detection_method"], "ml")
            self.assertGreaterEqual(alert["ml_probability"], cfg_thresh)
            self.assertTrue(len(alert["evidence"].get("top_contributing_features", [])) > 0)

    def test_06_scenario_c_benign_pcap(self) -> None:
        with open("samples/benign_traffic.pcap", "rb") as f:
            res = process_pcap_bytes_pipeline("benign_traffic.pcap", f.read(), db_path=self.temp_db.name)
        self.assertEqual(res["status"], "completed")
        self.assertGreaterEqual(res["total_flows"], 3)
        self.assertEqual(res["total_alerts"], 0)

    def test_07_scenario_d_missing_engines_never_silent(self) -> None:
        with open("samples/attack_signature.pcap", "rb") as f:
            raw = f.read()
        res_no_suri = process_pcap_bytes_pipeline(
            "attack_signature.pcap", raw, db_path=self.temp_db.name, force_suricata_unavailable=True
        )
        self.assertEqual(res_no_suri["engine_status"]["suricata"], "unavailable")

        with open("samples/suspicious_unmatched_ml.pcap", "rb") as f:
            raw_ml = f.read()
        res_no_model = process_pcap_bytes_pipeline(
            "suspicious_unmatched_ml.pcap", raw_ml, db_path=self.temp_db.name, force_model_missing=True
        )
        self.assertEqual(res_no_model["engine_status"]["model"], "missing")

    def test_08_invalid_pcap_validation(self) -> None:
        with self.assertRaises(PcapValidationError):
            extract_flows_from_pcap("invalid.txt", b"hello world")
        with self.assertRaises(PcapValidationError):
            extract_flows_from_pcap("empty.pcap", b"")
        with self.assertRaises(PcapValidationError):
            extract_flows_from_pcap("corrupt.pcap", b"NOT_A_PCAP_HEADER_AT_ALL_1234567890")


if __name__ == "__main__":
    unittest.main()
