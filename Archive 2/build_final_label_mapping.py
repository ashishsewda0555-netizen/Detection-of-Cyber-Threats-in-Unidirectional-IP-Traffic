import pandas as pd

CLASSIC_SYN_FLOOD = [2, 3, 4, 5, 6, 7, 8, 9, 19, 20, 21]
HIGH_VOLUME_SYN_FLOOD = [0, 1, 10, 11, 12, 13, 14, 15, 16, 17, 18]

rows = []
for i in CLASSIC_SYN_FLOOD:
    rows.append({"source_file": f"{i}.pcap_Flow.csv", "label": "syn_flood_classic"})
for i in HIGH_VOLUME_SYN_FLOOD:
    rows.append({"source_file": f"{i}.pcap_Flow.csv", "label": "syn_flood_high_volume"})
rows.append({"source_file": "benign.pcap_Flow.csv", "label": "benign"})

mapping_df = pd.DataFrame(rows)
mapping_df.to_csv("label_mapping_final.csv", index=False)
print("Saved label_mapping_final.csv")
print(mapping_df)