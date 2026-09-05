"""
Phase 2 — Inject Synthetic Port Scan Training Data
====================================================
Since Phase 1 only captured SYN flood + benign traffic, this script
generates realistic port scan windows and appends them to
windowed_features.csv so the model can learn to distinguish:

  DDoS (high volume, 1 port)  vs  Port Scan (low volume, many ports)

Port scan characteristics:
  - Low packet/flow rate (scanner probes slowly)
  - Low unique_src_count (single scanner IP)
  - HIGH unique_dst_ports (scanning thousands of ports)
  - Moderate syn_ack_ratio (some ports respond, most don't)
  - Small packet sizes (SYN probes are tiny)

Usage:
    python inject_port_scan.py
"""

import numpy as np
import pandas as pd

INPUT_CSV = "windowed_features.csv"
N_WINDOWS = 50  # Number of synthetic port scan windows to generate
LABEL = "port_scan"

np.random.seed(42)


def generate_port_scan_windows(n=N_WINDOWS):
    """Generate n synthetic port scan feature windows."""
    rows = []
    base_time = pd.Timestamp("2026-09-05 03:00:00")

    for i in range(n):
        # Port scans are slow and methodical
        n_ports_scanned = np.random.randint(50, 500)
        total_pkts = np.random.randint(n_ports_scanned, n_ports_scanned * 3)
        
        # Most probes get no response (closed/filtered ports)
        response_rate = np.random.uniform(0.02, 0.15)
        fwd_pkts = int(total_pkts * (1 - response_rate))
        bwd_pkts = total_pkts - fwd_pkts
        
        syn_count = int(fwd_pkts * np.random.uniform(0.85, 0.98))
        # Some ports respond with SYN-ACK, others with RST
        ack_count = int(bwd_pkts * np.random.uniform(0.3, 0.7))

        rows.append({
            "Dst_IP": f"192.168.100.{np.random.randint(1, 10)}",
            "Window_Start": base_time + pd.Timedelta(seconds=i * 5),
            "flow_rate": total_pkts / 5.0,
            "packet_rate": total_pkts / 5.0,
            "fwd_bwd_ratio": fwd_pkts / (bwd_pkts + 1),
            "unique_src_count": np.random.randint(1, 3),  # Single scanner
            "src_ip_entropy": np.random.uniform(0.0, 0.5),  # Very low entropy
            "syn_flag_sum": syn_count,
            "ack_flag_sum": ack_count,
            "syn_ack_ratio": syn_count / (ack_count + 1),
            "avg_packet_size": np.random.uniform(54.0, 74.0),  # SYN probes are tiny
            "packet_size_std": np.random.uniform(2.0, 12.0),
            "unique_dst_ports": n_ports_scanned,  # THE KEY FEATURE: many ports
            "Label": LABEL,
        })

    return pd.DataFrame(rows)


def main():
    print("Loading existing windowed features...")
    df = pd.read_csv(INPUT_CSV)
    print(f"  Existing windows: {len(df)}")
    print(f"  Existing labels: {df['Label'].value_counts().to_dict()}")

    print(f"\nGenerating {N_WINDOWS} synthetic port scan windows...")
    port_scan_df = generate_port_scan_windows()

    # Ensure column alignment
    for col in df.columns:
        if col not in port_scan_df.columns:
            port_scan_df[col] = 0
    for col in port_scan_df.columns:
        if col not in df.columns:
            df[col] = 0

    updated_df = pd.concat([df, port_scan_df], ignore_index=True)
    updated_df.to_csv(INPUT_CSV, index=False)

    print(f"\nUpdated windowed_features.csv:")
    print(f"  Total windows: {len(updated_df)}")
    print(f"  Label distribution:")
    print(updated_df["Label"].value_counts())
    print("\nPort scan injection complete!")


if __name__ == "__main__":
    main()
