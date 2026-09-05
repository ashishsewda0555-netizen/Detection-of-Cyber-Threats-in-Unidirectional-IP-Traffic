import pandas as pd

# Load existing dataset
df = pd.read_csv("windowed_features.csv")

# 4 synthetic stealth/zero-day anomaly vectors
synthetic_rows = [
    # Vector 1: Distributed low-rate stealth port sweep (massive IP spread, low volume)
    {
        "Dst_IP": "192.168.56.103",
        "Window_Start": "2026-09-03 18:38:00",
        "flow_rate": 2.4,
        "packet_rate": 5.2,
        "fwd_bwd_ratio": 1.1,
        "unique_src_count": 480,  # Extreme outlier: normal benign is 1-5
        "src_ip_entropy": 6.12,
        "syn_flag_sum": 3,
        "ack_flag_sum": 3,
        "syn_ack_ratio": 1.0,
        "avg_packet_size": 64.0,
        "packet_size_std": 8.5,
        "Label": "ddos_unknown_variant",
    },
    # Vector 2: Coordinated micro-probe sweep
    {
        "Dst_IP": "192.168.56.103",
        "Window_Start": "2026-09-03 18:38:05",
        "flow_rate": 3.8,
        "packet_rate": 8.0,
        "fwd_bwd_ratio": 1.05,
        "unique_src_count": 620,  # Severe botnet dispersion
        "src_ip_entropy": 6.35,
        "syn_flag_sum": 4,
        "ack_flag_sum": 4,
        "syn_ack_ratio": 1.0,
        "avg_packet_size": 72.0,
        "packet_size_std": 11.2,
        "Label": "ddos_unknown_variant",
    },
    # Vector 3: Payload anomaly / Jumbo buffer overflow probe (normal rate, extreme packet size)
    {
        "Dst_IP": "192.168.56.103",
        "Window_Start": "2026-09-03 18:38:10",
        "flow_rate": 1.6,
        "packet_rate": 3.4,
        "fwd_bwd_ratio": 1.0,
        "unique_src_count": 2,
        "src_ip_entropy": 0.69,
        "syn_flag_sum": 1,
        "ack_flag_sum": 2,
        "syn_ack_ratio": 0.5,
        "avg_packet_size": 1492.0,  # Extreme outlier: normal handshake/control is ~60-150 bytes
        "packet_size_std": 0.0,
        "Label": "ddos_unknown_variant",
    },
    # Vector 4: Asymmetric low-volume handshake anomaly
    {
        "Dst_IP": "192.168.56.103",
        "Window_Start": "2026-09-03 18:38:15",
        "flow_rate": 2.0,
        "packet_rate": 4.6,
        "fwd_bwd_ratio": 5.2,
        "unique_src_count": 2500,
        "src_ip_entropy": 9.5,
        "syn_flag_sum": 2,
        "ack_flag_sum": 0,
        "syn_ack_ratio": 2.5,
        "avg_packet_size": 52.0,
        "packet_size_std": 4.2,
        "Label": "ddos_unknown_variant",
    },
]

# Ensure column compatibility with existing dataframe columns
synthetic_df = pd.DataFrame(synthetic_rows)
for col in df.columns:
    if col not in synthetic_df.columns:
        synthetic_df[col] = 0

# Insert at the beginning or append at the end
updated_df = pd.concat([synthetic_df, df], ignore_index=True)
updated_df.to_csv("windowed_features.csv", index=False)
print(f"Injected {len(synthetic_rows)} zero-day anomaly windows into windowed_features.csv")