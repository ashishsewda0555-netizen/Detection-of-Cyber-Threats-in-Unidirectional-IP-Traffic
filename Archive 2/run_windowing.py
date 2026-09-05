import pandas as pd

print("Loading merged dataset...")
df = pd.read_csv("ml_ready_data.csv")

# --- Debug: see exactly what you have ---
print("Columns in file:", df.columns.tolist())

# --- Robust column matcher: strips whitespace/case, tries known CICFlowMeter variants ---
def find_column(df, candidates):
    normalized = {c.strip().lower(): c for c in df.columns}
    for cand in candidates:
        key = cand.strip().lower()
        if key in normalized:
            return normalized[key]
    raise KeyError(f"None of {candidates} found. Actual columns: {df.columns.tolist()}")

fwd_col = find_column(df, ["Total Fwd Packets", "Tot Fwd Pkts", "Fwd Pkt Cnt", "Subflow Fwd Packets"])
bwd_col = find_column(df, ["Total Backward Packets", "Tot Bwd Pkts", "Bwd Pkt Cnt", "Subflow Bwd Packets"])
dst_ip_col = find_column(df, ["Dst IP", "Destination IP", "dst_ip"])
ts_col = find_column(df, ["Timestamp", "timestamp"])

print(f"Using columns: fwd={fwd_col}, bwd={bwd_col}, dst_ip={dst_ip_col}, ts={ts_col}")

df[ts_col] = pd.to_datetime(df[ts_col], format="mixed", dayfirst=True)

print("Grouping flows into 5-second windows...")
windowed_data = []

for (dst_ip, window), group in df.groupby([dst_ip_col, pd.Grouper(key=ts_col, freq="5s")]):
    if not group.empty:
        windowed_data.append({
            "Dst IP": dst_ip,
            "Window_Start": window,
            "Total_Flows": len(group),
            "Total_Fwd_Packets": group[fwd_col].sum(),
            "Total_Bwd_Packets": group[bwd_col].sum(),
            "Label": "Unknown"
        })

final_df = pd.DataFrame(windowed_data)
final_df.to_csv("windowed_features.csv", index=False)
print("Windowing complete! Saved to windowed_features.csv")