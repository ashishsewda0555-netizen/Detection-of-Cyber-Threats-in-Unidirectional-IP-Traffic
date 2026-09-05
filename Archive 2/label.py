import pandas as pd

print("Loading windowed features...")
df = pd.read_csv("windowed_features.csv")

FLOW_THRESHOLD = 50 

df["Label"] = df["Total_Flows"].apply(lambda x: 1 if x > FLOW_THRESHOLD else 0)

print("\nLabel Distribution:")
print(df["Label"].value_counts())

df.to_csv("labeled_features.csv", index=False)
print("\nDataset labeled and saved to labeled_features.csv")