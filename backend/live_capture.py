"""
live_capture.py — In-Memory Scapy Sniffer for DDoS Sentinel

Captures live network traffic in 5-second windows using Scapy, extracts
the exact feature vector the ML model expects, and POSTs it as JSON
directly to the FastAPI backend for in-memory scoring.

    live_capture.py  ──POST JSON──►  api_server.py  ──SSE push──►  React Frontend
       (Scapy)                       (FastAPI)                     (EventSource)

NO disk I/O in the live inference path. Zero CSV files.

Configuration is loaded from .env (single source of truth):
    VICTIM_IP=192.168.100.2
    SNIFFER_INTERFACE=Ethernet 3
    API_HOST=0.0.0.0
    API_PORT=8000

Start with:
    python live_capture.py
"""

import os
import threading
import time

import numpy as np
import pandas as pd
import requests
from dotenv import load_dotenv
from scapy.all import IP, TCP, sniff

# ──────────────────────────────────────────────
# Configuration from .env
# ──────────────────────────────────────────────
load_dotenv()

VICTIM_IP = os.getenv("VICTIM_IP", "192.168.100.2")
INTERFACE = os.getenv("SNIFFER_INTERFACE", "Ethernet 3")
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = os.getenv("API_PORT", "8000")

# Windows fix: Clients cannot connect to meta-address 0.0.0.0 directly.
_client_host = "127.0.0.1" if API_HOST == "0.0.0.0" else API_HOST
API_SCORE_URL = f"http://{_client_host}:{API_PORT}/api/score"
API_HEALTH_URL = f"http://{_client_host}:{API_PORT}/api/health"


def extract_features(packets: list, victim_ip: str) -> dict:
    """Extract the feature vector from a 5-second packet window.

    Returns the exact feature dictionary that scorer.score_window() expects.
    All computation is in-memory — no disk writes.
    """
    fwd_pkts, bwd_pkts = 0, 0
    syn_flags, ack_flags = 0, 0
    packet_sizes = []
    unique_ips = set()
    unique_ports = set()

    for pkt in packets:
        if IP in pkt:
            packet_sizes.append(len(pkt))

            # Directionality (Forward = Inbound to Victim)
            if pkt[IP].dst == victim_ip:
                fwd_pkts += 1
                unique_ips.add(pkt[IP].src)
            else:
                bwd_pkts += 1

            # TCP Flags and Ports
            if TCP in pkt:
                flags = pkt[TCP].flags
                if "S" in flags:
                    syn_flags += 1
                if "A" in flags:
                    ack_flags += 1
                unique_ports.add(pkt[TCP].dport)

    return {
        "Dst_IP": victim_ip,
        "Window_Start": str(pd.Timestamp.now(tz="UTC")),
        "flow_rate": (fwd_pkts + bwd_pkts) / 5.0,
        "packet_rate": (fwd_pkts + bwd_pkts) / 5.0,
        "fwd_bwd_ratio": fwd_pkts / (bwd_pkts + 1),
        "unique_src_count": len(unique_ips),
        "syn_flag_sum": syn_flags,
        "ack_flag_sum": ack_flags,
        "syn_ack_ratio": syn_flags / (ack_flags + 1),
        "avg_packet_size": float(np.mean(packet_sizes)) if packet_sizes else 0.0,
        "packet_size_std": float(np.std(packet_sizes)) if packet_sizes else 0.0,
        "unique_dst_ports": len(unique_ports),
    }


windows_sent = 0
errors = 0

def send_to_api(features: dict):
    global windows_sent, errors
    try:
        response = requests.post(
            API_SCORE_URL,
            json=features,
            timeout=2,
        )

        if response.status_code == 200:
            verdict = response.json()
            windows_sent += 1

            is_alert = verdict.get("is_alert", False)
            threat = verdict.get("threat_class", "benign")
            severity = verdict.get("severity", "—")
            confidence = verdict.get("confidence", 0)

            status_icon = "🚨" if is_alert else "✅"
            total_captured = int(features.get("packet_rate", 0) * 5)
            print(
                f"[{time.strftime('%X')}] {status_icon} "
                f"{total_captured} pkts | "
                f"{features.get('unique_src_count', 0)} src IPs | "
                f"verdict={threat} ({severity}) "
                f"conf={confidence:.3f} | "
                f"sent={windows_sent}"
            )
        else:
            errors += 1
            print(
                f"[{time.strftime('%X')}] ❌ API error {response.status_code}: "
                f"{response.text[:120]}"
            )

    except requests.exceptions.RequestException as e:
        errors += 1
        print(f"[{time.strftime('%X')}] ❌ API connection error: {e.__class__.__name__}")


def main():
    global windows_sent, errors
    print(f"🛡️  DDoS Sentinel — Live Sniffer")
    print(f"   Victim IP   : {VICTIM_IP}")
    print(f"   Interface   : {INTERFACE}")
    print(f"   API endpoint: {API_SCORE_URL}")
    print(f"   Capturing 5-second windows. Press Ctrl+C to stop.\n")

    # Verify API is reachable before starting capture loop
    try:
        health = requests.get(API_HEALTH_URL, timeout=3)
        if health.status_code == 200:
            print(f"   ✅ API server is online: {health.json()}\n")
        else:
            print(f"   ⚠️  API returned status {health.status_code} — proceeding anyway.\n")
    except requests.ConnectionError:
        print(f"   ⚠️  Cannot reach API at {API_SCORE_URL}.")
        print(f"       Start the API first: python api_server.py")
        print(f"       Proceeding — will retry on each window.\n")

    while True:
        try:
            # Sniff traffic for exactly 5 seconds on the configured interface
            packets = sniff(
                iface=INTERFACE,
                timeout=5,
                filter=f"ip dst {VICTIM_IP} or ip src {VICTIM_IP}",
            )

            if not packets:
                continue

            total_captured = len(packets)

            # Extract features in memory
            features = extract_features(packets, VICTIM_IP)

            # Free packet memory immediately
            del packets

            # Dispatch HTTP POST asynchronously so Scapy doesn't drop packets
            threading.Thread(target=send_to_api, args=(features,), daemon=True).start()

        except KeyboardInterrupt:
            print(f"\n🛑 Stopped by user. Windows sent: {windows_sent}, Errors: {errors}")
            break
        except Exception as e:
            errors += 1
            print(f"[{time.strftime('%X')}] ERROR in capture window (skipped): {e}")
            continue


if __name__ == "__main__":
    main()