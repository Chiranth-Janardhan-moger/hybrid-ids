#!/usr/bin/env python3
"""
Windows Live Network Interface Sniffer for Hybrid IDS.
Captures live packets from your active Windows Wi-Fi/Ethernet adapter in 5-second windows using Scapy,
uploads each micro-batch to the Hybrid IDS backend (/api/jobs), and prints a live console alert
whenever suspicious or malicious traffic ("Something fishy is going on!") is detected.

Usage on Windows (run PowerShell as Administrator):
  .\.venv\Scripts\Activate.ps1
  python backend\live_sniffer.py --url http://localhost:3000 --interval 5
"""
import argparse
import os
import tempfile
import time
import urllib.request
import json


def upload_pcap_to_backend(api_url: str, pcap_path: str) -> dict:
    boundary = "----HybridIDSLiveBoundary7MA4YWxkTrZu0gW"
    filename = os.path.basename(pcap_path)
    with open(pcap_path, "rb") as f:
        file_bytes = f.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/api/jobs",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        job_res = json.loads(resp.read().decode("utf-8"))

    job_id = job_res["job_id"]
    with urllib.request.urlopen(f"{api_url.rstrip('/')}/api/jobs/{job_id}", timeout=10) as jresp:
        return json.loads(jresp.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid IDS Live Network Sniffer")
    parser.add_argument("--url", default="http://localhost:3000", help="Hybrid IDS server URL")
    parser.add_argument("--iface", default=None, help="Network interface name (default: Scapy auto-detect)")
    parser.add_argument("--interval", type=int, default=5, help="Capture window in seconds")
    args = parser.parse_args()

    try:
        from scapy.all import sniff, wrpcap  # type: ignore
    except ImportError:
        print("Error: Scapy is required for live NIC capture. Run: pip install scapy")
        return

    print(f"[*] Starting Hybrid IDS Live Traffic Sniffer (window={args.interval}s -> {args.url})")
    window_idx = 1
    while True:
        print(f"\n[Window #{window_idx}] Sniffing live packets for {args.interval} seconds...")
        packets = sniff(iface=args.iface, timeout=args.interval)
        if not packets:
            print("  -> No packets captured in window.")
            window_idx += 1
            continue

        with tempfile.NamedTemporaryFile(prefix=f"live_win_{window_idx}_", suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            wrpcap(tmp_path, packets)
            result = upload_pcap_to_backend(args.url, tmp_path)
            flows = result.get("total_flows", 0)
            alerts = result.get("total_alerts", 0)
            sig_a = result.get("signature_alerts", 0)
            ml_a = result.get("ml_alerts", 0)

            if alerts > 0:
                print(
                    f"  [!] SOMETHING FISHY IS GOING ON! {alerts} threat(s) detected in {flows} flows "
                    f"(Signature={sig_a}, ML={ml_a}) -> Job {result['id']}"
                )
            else:
                print(f"  [OK] Traffic normal ({flows} flows analyzed, 0 threats).")
        except Exception as exc:
            print(f"  [!] Live batch analysis error: {exc}")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

        window_idx += 1
        time.sleep(0.5)


if __name__ == "__main__":
    main()
