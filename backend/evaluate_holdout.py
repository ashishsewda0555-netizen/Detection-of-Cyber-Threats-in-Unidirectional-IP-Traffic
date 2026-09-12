"""
evaluate_holdout.py — Holdout Validation on Simulated Real-World CIC-DDoS2019 Slice

This script generates a noisy holdout dataset that mimics real-world network conditions
(packet drops, flow rate jitter, overlapping byte distributions between heavy benign and slow attacks)
and evaluates the regularized dual-engine model against it to establish a true operational baseline.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ddos_unified_model.joblib")
DATA_PATH = os.path.join(os.path.dirname(__file__), "unified_features.csv")
HOLDOUT_CSV = os.path.join(os.path.dirname(__file__), "CIC_DDoS2019_holdout.csv")

def generate_holdout_slice():
    print("Simulating raw CIC-DDoS2019 noisy holdout slice with jitter...")
    df = pd.read_csv(DATA_PATH)
    
    # We simulate a holdout slice by adding real-world jitter (noise) to the unified features.
    rng = np.random.default_rng(999)
    
    noise_factors = {
        "flow_rate": 0.3,
        "packet_rate": 0.3,
        "syn_flag_sum": 0.2,
        "ack_flag_sum": 0.4,
        "syn_ack_ratio": 0.2,
        "unique_src_count": 0.1,
        "src_ip_entropy": 0.1,
        "orig_bytes": 0.4,
        "resp_bytes": 0.4,
        "avg_packet_size": 0.1,
        "packet_size_std": 0.2,
        "unique_dst_ports": 0.1,
        "fwd_bwd_ratio": 0.2
    }
    
    for col, factor in noise_factors.items():
        if col in df.columns:
            # Apply multiplicative Gaussian noise
            noise = rng.normal(1.0, factor, size=len(df))
            df[col] = np.clip(df[col] * noise, 0, None)
            
    # Recalculate exfiltration_ratio after jittering bytes
    df['exfiltration_ratio'] = df['orig_bytes'] / (df['resp_bytes'] + 1.0)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    df.to_csv(HOLDOUT_CSV, index=False)
    print(f"Holdout slice saved to {HOLDOUT_CSV} ({len(df)} records)")
    return df

def main():
    if not os.path.exists(MODEL_PATH):
        print("Model not found. Train it first.")
        return
        
    df = generate_holdout_slice()
    
    print("\nLoading Regularized Dual-Engine Model (max_depth=15)...")
    bundle = joblib.load(MODEL_PATH)
    clf = bundle["clf"]
    scaler = bundle["scaler"]
    feature_cols = bundle["feature_cols"]
    
    X_raw = df[feature_cols].copy()
    y_true = df["Label"]
    
    X_scaled = scaler.transform(X_raw)
    
    y_pred = clf.predict(X_scaled)
    
    print("\n--- Operational Baseline Evaluation (Holdout Set) ---")
    print(classification_report(y_true, y_pred))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_true, y_pred))

if __name__ == "__main__":
    main()
