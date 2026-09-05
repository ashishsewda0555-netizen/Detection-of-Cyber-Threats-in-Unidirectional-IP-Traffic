"""
Phase 1 Verification Script
============================
Run this AFTER you have completed the two manual captures:
  - spoofed_flood_01.pcap
  - benign_deep_01.pcap

Usage:
    python verify_phase1.py

It will check each PCAP and report whether it is valid for retraining.
"""

import sys
import os

try:
    from scapy.all import rdpcap, IP, TCP
except ImportError:
    print("ERROR: scapy is not installed. Run: pip install scapy")
    sys.exit(1)

VICTIM_IP = "192.168.100.2"

REQUIRED_FILES = {
    "spoofed_flood_01.pcap": {
        "min_packets": 5000,
        "check_rand_src": True,
        "label": "SPOOFED_SYN_FLOOD",
    },
    "benign_deep_01.pcap": {
        "min_packets": 1000,
        "check_rand_src": False,
        "label": "BENIGN",
    },
}


def verify_pcap(filepath: str, config: dict) -> bool:
    print(f"\n--- Verifying: {filepath} ---")

    if not os.path.exists(filepath):
        print(f"  [FAIL] File not found: {filepath}")
        print(f"         Complete the manual capture first, then re-run this script.")
        return False

    print(f"  [OK]   File exists ({os.path.getsize(filepath) / 1024:.1f} KB)")

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"  [FAIL] Could not read PCAP: {e}")
        return False

    total = len(packets)
    ip_packets = [p for p in packets if IP in p]
    tcp_packets = [p for p in ip_packets if TCP in p]

    print(f"  [INFO] Total packets    : {total:,}")
    print(f"  [INFO] IP packets       : {len(ip_packets):,}")
    print(f"  [INFO] TCP packets      : {len(tcp_packets):,}")

    if total < config["min_packets"]:
        print(f"  [WARN] Packet count ({total:,}) is below minimum ({config['min_packets']:,}).")
        print(f"         Capture may be too short — consider recapturing.")
    else:
        print(f"  [OK]   Packet count meets minimum threshold.")

    # Check source IP diversity (for spoofed flood)
    if config["check_rand_src"]:
        src_ips = set()
        syn_count = 0
        for pkt in tcp_packets:
            if pkt[IP].dst == VICTIM_IP:
                src_ips.add(pkt[IP].src)
                if "S" in pkt[TCP].flags and "A" not in pkt[TCP].flags:
                    syn_count += 1

        print(f"  [INFO] Unique source IPs : {len(src_ips):,}")
        print(f"  [INFO] SYN packets       : {syn_count:,}")

        if len(src_ips) < 5:
            print(f"  [FAIL] Only {len(src_ips)} unique source IPs found.")
            print(f"         The spoofed flood needs randomized source IPs.")
            print(f"         Use: hping3 --rand-source OR the nping FOR loop workaround.")
            return False
        else:
            print(f"  [OK]   Source IP entropy confirmed — {len(src_ips)} unique sources seen.")

    # Check label in capture_log
    if os.path.exists("capture_log.txt"):
        with open("capture_log.txt", "r") as f:
            log_content = f.read()
        basename = os.path.basename(filepath)
        if basename in log_content:
            print(f"  [OK]   File is logged in capture_log.txt.")
        else:
            print(f"  [WARN] File is NOT logged in capture_log.txt.")
            print(f"         Fill in the capture log entry for '{basename}' before proceeding.")

    print(f"  [PASS] {filepath} is valid for Phase 2 retraining.")
    return True


def main():
    print("=" * 60)
    print("  Phase 1 — Capture Verification")
    print("=" * 60)

    all_passed = True
    for filename, config in REQUIRED_FILES.items():
        passed = verify_pcap(filename, config)
        if not passed:
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("  RESULT: ALL CHECKS PASSED")
        print("  You are ready to proceed to Phase 2.")
        print("  Tell the agent: 'Phase 1 verified, proceed to Phase 2'")
    else:
        print("  RESULT: ONE OR MORE CHECKS FAILED")
        print("  Complete the manual captures listed above, then re-run:")
        print("  python verify_phase1.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
