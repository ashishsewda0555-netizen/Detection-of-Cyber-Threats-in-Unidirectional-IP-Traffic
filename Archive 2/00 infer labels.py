"""
Step 0: Since the pcap-to-attack-type mapping was lost, infer a label per
source_file from the traffic characteristics themselves (protocol, TCP flag
pattern, source-IP diversity). Outputs a suggested mapping for you to review
and correct before it's used as ground truth.

Prerequisite: re-run the fixed merge.py first so ml_ready_data.csv has a
'source_file' column.
"""

import pandas as pd

INPUT_CSV = "ml_ready_data.csv"
OUTPUT_CSV = "label_mapping_suggested.csv"


SPOOFED_SRC_IP_THRESHOLD = 20   


def suggest_label(group):
    if len(group) == 0:
        return "unknown", {}

    protocol_mode = group["Protocol"].mode().iloc[0]
    syn_sum = group["SYN Flag Count"].sum()
    ack_sum = group["ACK Flag Count"].sum()
    syn_ack_ratio = syn_sum / (ack_sum + 1)
    unique_src = group["Src IP"].nunique()
    unique_dst = group["Dst IP"].nunique()
    n_rows = len(group)

    stats = {
        "n_rows": n_rows,
        "protocol_mode": protocol_mode,
        "syn_sum": syn_sum,
        "ack_sum": ack_sum,
        "syn_ack_ratio": round(syn_ack_ratio, 2),
        "unique_src_ips": unique_src,
        "unique_dst_ips": unique_dst,
    }

    # Protocol 17 = UDP, 6 = TCP (standard IANA numbers, present in most
    # CICFlowMeter output as-is)
    if protocol_mode == 17:
        return "udp_amplification", stats

    if protocol_mode == 6:
        if syn_ack_ratio > 3:  # heavily SYN-skewed, handshake rarely completes
            if unique_src > SPOOFED_SRC_IP_THRESHOLD:
                return "spoofed_source_flood", stats
            else:
                return "syn_flood", stats
        else:
            return "uncertain_tcp", stats

    return "unknown_protocol", stats


def main():
    print("Loading merged dataset...")
    df = pd.read_csv(INPUT_CSV)
    df.columns = df.columns.str.strip()

    if "source_file" not in df.columns:
        raise SystemExit(
            "No 'source_file' column found. Re-run the fixed merge.py "
            "(the version that tags each row with os.path.basename(f)) first."
        )

    print(f"Found {df['source_file'].nunique()} source files.\n")

    rows = []
    for source_file, group in df.groupby("source_file"):
        if "benign" in source_file.lower():
            rows.append({"source_file": source_file, "suggested_label": "benign",
                         "n_rows": len(group), "protocol_mode": "-", "syn_sum": "-",
                         "ack_sum": "-", "syn_ack_ratio": "-", "unique_src_ips": "-",
                         "unique_dst_ips": "-"})
            continue

        label, stats = suggest_label(group)
        rows.append({"source_file": source_file, "suggested_label": label, **stats})

    result_df = pd.DataFrame(rows).sort_values("source_file")
    pd.set_option("display.width", 200)
    print(result_df.to_string(index=False))

    result_df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSaved suggestions to {OUTPUT_CSV}")
    print("\nNEXT STEP: open this CSV, eyeball each row, and fix any 'uncertain_tcp' "
          "or 'unknown_protocol' rows manually based on what you remember about that "
          "capture. Save your corrected version as label_mapping_final.csv with just "
          "two columns: source_file, label")


if __name__ == "__main__":
    main()