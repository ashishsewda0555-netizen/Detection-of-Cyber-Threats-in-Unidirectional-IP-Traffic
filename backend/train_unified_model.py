"""
train_unified_model.py — Train Dual-Engine ML on Unified Scapy + Zeek Schema

Schema (14 numeric features):
- Scapy Fast-Path: flow_rate, packet_rate, fwd_bwd_ratio, unique_src_count,
                   src_ip_entropy, syn_flag_sum, ack_flag_sum, syn_ack_ratio,
                   avg_packet_size, packet_size_std, unique_dst_ports
- Zeek Flow-Path:  orig_bytes, resp_bytes, exfiltration_ratio
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import RobustScaler

FEATURE_COLUMNS = [
    "flow_rate", "packet_rate", "fwd_bwd_ratio", "unique_src_count",
    "src_ip_entropy", "syn_flag_sum", "ack_flag_sum", "syn_ack_ratio",
    "avg_packet_size", "packet_size_std", "unique_dst_ports",
    "orig_bytes", "resp_bytes", "exfiltration_ratio"
]

MODEL_OUT = os.path.join(os.path.dirname(__file__), "ddos_unified_model.joblib")
TRAIN_FRACTION = 0.7

def main():
    input_csv = os.path.join(os.path.dirname(__file__), "unified_features.csv")
    if not os.path.exists(input_csv):
        print(f"Error: {input_csv} not found.")
        return
        
    print(f"Loading {input_csv}...")
    df = pd.read_csv(input_csv)
    
    # Clean data
    df = df.replace([np.inf, -np.inf], np.nan)
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].fillna(0)
    
    print(f"Class distribution:\n{df['Label'].value_counts()}")
    
    # Temporal Split
    train_parts, test_parts = [], []
    for label, group in df.groupby("Label"):
        if "Window_Start" in group.columns:
            group = group.sort_values("Window_Start")
        else:
            group = group.sample(frac=1, random_state=42)
            
        cutoff = int(len(group) * TRAIN_FRACTION)
        train_parts.append(group.iloc[:cutoff])
        test_parts.append(group.iloc[cutoff:])
        
    train_df = pd.concat(train_parts).reset_index(drop=True)
    test_df = pd.concat(test_parts).reset_index(drop=True)
    
    X_train_raw = train_df[FEATURE_COLUMNS].copy()
    X_test_raw = test_df[FEATURE_COLUMNS].copy()
    y_train = train_df["Label"]
    y_test = test_df["Label"]
    
    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)
    
    # Stage 1: Isolation Forest
    print("\nTraining Stage 1 (Isolation Forest)...")
    benign_mask = (y_train == "benign").values
    if not benign_mask.any():
        print("Warning: No benign samples in training set for Isolation Forest. Using all data.")
        benign_mask = np.ones(len(y_train), dtype=bool)
        
    iso_model = IsolationForest(contamination=0.05, random_state=42)
    iso_model.fit(X_train[benign_mask])
    
    raw_scores_benign = -iso_model.score_samples(X_train[benign_mask])
    score_min = float(raw_scores_benign.min())
    score_max = float(raw_scores_benign.max())
    
    # Stage 2: Random Forest
    print("Training Stage 2 (Random Forest with Regularization)...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42
    )
    clf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test)
    print("\n--- Evaluation ---")
    print(classification_report(y_test, y_pred))
    
    benign_mean = X_train_raw[benign_mask].mean()
    benign_std = X_train_raw[benign_mask].std().replace(0, 1e-9)
    
    bundle = {
        "iso_model": iso_model,
        "clf": clf,
        "scaler": scaler,
        "feature_cols": FEATURE_COLUMNS,
        "score_min": score_min,
        "score_max": score_max,
        "benign_mean": benign_mean,
        "benign_std": benign_std,
    }
    
    joblib.dump(bundle, MODEL_OUT)
    print(f"\nUnified Model saved to {MODEL_OUT}")

if __name__ == "__main__":
    main()
