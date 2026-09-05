import pandas as pd

df = pd.read_csv("ml_ready_data.csv")
df.columns = df.columns.str.strip()
df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True)
label_map = pd.read_csv("label_mapping_final.csv")
df = df.merge(label_map, on="source_file", how="left")

print("--- Real duration per source file ---")
for f, g in df.groupby("source_file"):
    span = g["Timestamp"].max() - g["Timestamp"].min()
    print(f"{f:25s} rows={len(g):8d} span={span} dst_ips={g['Dst IP'].unique()[:2]}")

print("\n--- Benign Dst IP check ---")
benign = df[df["label"] == "benign"]
print("Unique benign Dst IPs:", benign["Dst IP"].nunique())
print(benign["Dst IP"].value_counts().head(15))

