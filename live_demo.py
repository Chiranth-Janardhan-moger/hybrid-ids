#!/usr/bin/env python3
"""
Live Hybrid IDS / IPS Multi-Layer Terminal Traffic Runner (live_demo.py)
========================================================================
Sends 16 real network queries (4 Safe + 12 Multi-Layer Attacks) through the
Defense-in-Depth IPS pipeline and prints live verdicts:
  - Layer 0: Stateful IP Auto-Quarantine (0.01ms pre-filter memory drop)
  - Layer 1: Suricata Signature Engine (SQLi, Log4j, Path Traversal, Command Injection, XSS)
  - Layer 2: Random Forest Flow ML Engine (Zero-Day TCP SYN Flood, Slowloris Starvation)
  - Layer 3A: Shannon Entropy & Obfuscation DPI (XOR Shellcode, Polymorphic Webshell)
  - Layer 3B: Zero-Trust Honeypot Decoy Trap (/.env, /.aws/credentials)
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

if os.name == "nt":
    os.system("")

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
MAGENTA = "\033[95m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GRAY = "\033[90m"


def api_request(base_url: str, path: str, method: str = "GET", payload: dict | None = None) -> dict:
    url = f"{base_url.rstrip('/')}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    api_key = os.environ.get("ADMIN_API_KEY", "hybrid-ids-admin-secret")
    headers = {"Content-Type": "application/json", "X-API-Key": api_key} if data is not None else {"X-API-Key": api_key}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        print(f"\n{RED}{BOLD}[ERROR]{RESET} Could not connect to Hybrid IDS server at {base_url}")
        print(f"Make sure the server is running (http://localhost:3000). Details: {exc}\n")
        sys.exit(1)


def run_single_pass(base_url: str, delay_sec: float = 0.20, attacks_only: bool = False) -> None:
    catalog = api_request(base_url, "/api/ips/catalog?reset_quarantine=1", method="GET")
    block_on = bool(catalog.get("block_mode_enabled", False))
    queries = catalog.get("queries", [])

    if attacks_only:
        queries = [q for q in queries if q.get("query_type") == "ATTACK"]

    mode_badge = (
        f"{RED}{BOLD}ON  (3-LAYER IPS ACTIVE — BLOCKING + AUTO-QUARANTINE){RESET}"
        if block_on
        else f"{YELLOW}{BOLD}OFF (IDS MONITOR ONLY — NOT BLOCKING ATTACKS){RESET}"
    )

    print("\n" + "=" * 120)
    print(f" {BOLD}{CYAN}HYBRID IDS / IPS — DEFENSE-IN-DEPTH ATTACK MITIGATION DEMO{RESET}")
    print(f" Target Server : {base_url}")
    print(f" Firewall Mode : {mode_badge}")
    print(f" Query Suite   : {len(queries)} scenarios ({'Attacks Only' if attacks_only else 'Mixed Safe + Attacks'})")
    print("=" * 120)
    print(
        f" {'#':<2} | {'TYPE':<6} | {'SOURCE IP':<15} | {'QUERY / SCENARIO':<40} | {'VERDICT & SECURITY LAYER'}"
    )
    print("-" * 120)

    safe_allowed = 0
    attack_unblocked = 0
    attack_blocked = 0
    quarantine_drops = 0
    last_ips_status = {}

    for idx, q in enumerate(queries, start=1):
        resp = api_request(base_url, "/api/ips/query", method="POST", payload=q)
        entry = resp["entry"]
        last_ips_status = resp.get("ips_status", {})

        qtype = entry["query_type"]
        src_ip = entry["src_ip"]
        label = entry["label"][:40]
        action = entry["action"]
        risk = entry["risk_score"]
        detail = entry["detection_detail"]

        type_str = f"{GREEN}SAFE  {RESET}" if qtype == "SAFE" else f"{RED}ATTACK{RESET}"

        if action == "ALLOWED":
            safe_allowed += 1
            verdict_str = f"{GREEN}{BOLD}[200 ALLOWED]{RESET} {GREEN}{detail[:54]}{RESET}"
        elif action == "ALLOWED_UNBLOCKED":
            attack_unblocked += 1
            verdict_str = (
                f"{YELLOW}{BOLD}[200 ALLOWED (Block OFF)]{RESET} "
                f"{YELLOW}Risk {risk} | {detail[:46]}{RESET}"
            )
        elif action == "QUARANTINED":
            attack_blocked += 1
            quarantine_drops += 1
            verdict_str = (
                f"{MAGENTA}{BOLD}[403 QUARANTINED]{RESET} "
                f"{MAGENTA}0.01ms Drop! {detail[:48]}{RESET}"
            )
        else:
            attack_blocked += 1
            verdict_str = (
                f"{RED}{BOLD}[403 BLOCKED]{RESET} "
                f"{RED}Risk {risk} | {detail[:52]}{RESET}"
            )

        print(f" {idx:<2} | {type_str} | {src_ip:<15} | {label:<40} | {verdict_str}")
        if delay_sec > 0:
            time.sleep(delay_sec)

    quarantined_ips = [item["ip"] for item in last_ips_status.get("quarantined_ips", [])]
    print("-" * 120)
    print(
        f" {BOLD}SUMMARY:{RESET} "
        f"{GREEN}Safe Allowed: {safe_allowed}{RESET}  |  "
        f"{YELLOW}Attacks Allowed (Block OFF): {attack_unblocked}{RESET}  |  "
        f"{RED}Attacks Blocked: {attack_blocked}{RESET}  |  "
        f"{MAGENTA}Quarantine Drops: {quarantine_drops}{RESET}"
    )
    if quarantined_ips:
        print(f" {BOLD}{MAGENTA}QUARANTINED BLACKLIST IPs:{RESET} {', '.join(quarantined_ips)}")
    print("=" * 120 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid IDS/IPS 3-Layer Terminal Demo")
    parser.add_argument(
        "--url",
        default="http://localhost:3000",
        help="Base URL of the Hybrid IDS server (default: http://localhost:3000)",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Continuously run every 4 seconds",
    )
    parser.add_argument(
        "--set-block",
        choices=["on", "off"],
        help="Toggle IPS Block Mode ON or OFF before running",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Run without delays between queries for rapid execution",
    )
    parser.add_argument(
        "--attacks-only",
        action="store_true",
        help="Execute only the attack scenarios",
    )
    args = parser.parse_args()

    if args.set_block:
        enable = args.set_block == "on"
        api_request(args.url, "/api/ips/toggle", method="POST", payload={"block_mode_enabled": enable})

    delay = 0.04 if args.fast else 0.20

    if args.loop:
        try:
            while True:
                run_single_pass(args.url, delay_sec=delay, attacks_only=args.attacks_only)
                print(f"{GRAY}Waiting 4 seconds before next pass (Press Ctrl+C to stop)...{RESET}")
                time.sleep(4.0)
        except KeyboardInterrupt:
            print("\nStopped live_demo.py.")
    else:
        run_single_pass(args.url, delay_sec=delay, attacks_only=args.attacks_only)


if __name__ == "__main__":
    main()
