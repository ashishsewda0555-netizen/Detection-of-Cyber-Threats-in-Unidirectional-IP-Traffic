"""
Step 1 (v3): Chunk each (source_file, Dst_IP) group into fixed-size windows
of N consecutive rows, sorted by time. Grouping by Dst_IP (not just
source_file) matters for benign traffic, which legitimately talks to many
different destinations (305 unique in your capture) -- attack files are
already ~99% one destination, so this doesn't change their behavior, but it
stops benign traffic from being collapsed down to a single destination.

A single uniform ROWS_PER_WINDOW is used for all classes deliberately: using
different chunk sizes per class would make Total_Flows trivially predictive
of the label by construction, which is leakage, not real signal.
"""

import numpy as np
import pandas as pd

INPUT_CSV = "ml_ready_data.csv"
LABEL_MAP_CSV = "label_mapping_final.csv"
OUTPUT_CSV = "windowed_features.csv"

ROWS_PER_WINDOW = 30
MIN_ELAPSED_SECONDS = 0.001
MIN_PARTIAL_CHUNK_FRACTION = 0.2


def entropy(series):
    if len(series) == 0:
        return 0.0
    counts = series.value_counts(normalize=True)
    return float(-(counts * np.log2(counts)).sum())


def main():
    print("Loading raw flow data...")
    df = pd.read_csv(INPUT_CSV)
    df.columns = df.columns.str.strip()

    print("Loading label mapping...")
    label_map = pd.read_csv(LABEL_MAP_CSV)
    df = df.merge(label_map, on="source_file", how="left")

    unmapped = df[df["label"].isna()]["source_file"].unique()
    if len(unmapped) > 0:
        raise SystemExit(f"These source_file values have no label mapping: {unmapped}")

    ts_col = "Timestamp"
    dst_col = "Dst IP"
    src_col = "Src IP"
    fwd_col = "Total Fwd Packet"
    bwd_col = "Total Bwd packets"
    syn_col = "SYN Flag Count"
    ack_col = "ACK Flag Count"
    pktlen_mean_col = "Packet Length Mean"
    
    # Determine the correct port column name (CICFlowMeter varies slightly)
    dst_port_col = "Dst Port" if "Dst Port" in df.columns else "Destination Port"

    df[ts_col] = pd.to_datetime(df[ts_col], format="mixed", dayfirst=True)

    windowed_data = []
    
    WINDOW_SECONDS = 5

    print(f"Bucketing each (source_file, Dst_IP) group into {WINDOW_SECONDS}-second windows...")
    for (source_file, dst_ip), group in df.groupby(["source_file", dst_col]):
        # Group by 5s intervals based on the timestamp
        grouper = group.groupby(pd.Grouper(key=ts_col, freq=f'{WINDOW_SECONDS}s'))
        
        for window_start, chunk in grouper:
            total_flows = len(chunk)
            if total_flows == 0:
                continue
                
            total_fwd = chunk[fwd_col].sum()
            total_bwd = chunk[bwd_col].sum()
            
            # Rates must strictly divide by the wall-clock window size (5.0s)
            elapsed = float(WINDOW_SECONDS)

            windowed_data.append({
                "Dst_IP": dst_ip,
                "Window_Start": window_start,
                "elapsed_seconds": elapsed,
                "Total_Flows": total_flows,
                "flow_rate": (total_fwd + total_bwd) / elapsed,
                "packet_rate": (total_fwd + total_bwd) / elapsed,
                "fwd_bwd_ratio": total_fwd / (total_bwd + 1),
                "unique_src_count": chunk[src_col].nunique(),
                "src_ip_entropy": entropy(chunk[src_col]),
                "syn_flag_sum": chunk[syn_col].sum(),
                "ack_flag_sum": chunk[ack_col].sum(),
                "syn_ack_ratio": chunk[syn_col].sum() / (chunk[ack_col].sum() + 1),
                "avg_packet_size": chunk[pktlen_mean_col].mean(),
                "packet_size_std": chunk[pktlen_mean_col].std() if total_flows > 1 else 0.0,
                "unique_dst_ports": chunk[dst_port_col].nunique() if dst_port_col in df.columns else 1,
                "Label": chunk["label"].iloc[0],
                "source_file": source_file,
            })

    final_df = pd.DataFrame(windowed_data)
    final_df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nWindowing complete! {len(final_df)} windows saved to {OUTPUT_CSV}")
    print(final_df["Label"].value_counts())
    print("\nWindows per label per source file (benign should now span many rows):")
    print(final_df.groupby(["Label", "source_file"]).size())


if __name__ == "__main__":
    main()