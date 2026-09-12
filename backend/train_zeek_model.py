"""
train_zeek_model.py — Train a Dual-Engine DDoS Detector on Zeek Flow Features (v2)

Reads a labeled zeek_features_v2.csv and trains:
  Stage 1: IsolationForest  — zero-day anomaly detector (unsupervised)
  Stage 2: RandomForest      — sub-type classifier (supervised)

Feature columns (8 numeric features):
    id.orig_p, id.resp_p, orig_bytes, resp_bytes,
    exfiltration_ratio, syn_flag_count, ack_flag_count,
    syn_ack_ratio, flow_rate

Output: ddos_dual_engine_model.joblib  (compatible with scorer.py)

If no labeled CSV is found, generates a realistic synthetic dataset
with proper noise to avoid overfitting.

Usage:
    python train_zeek_model.py                         # uses synthetic data
    python train_zeek_model.py -i labeled_flows.csv    # custom input
"""

import argparse
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import RobustScaler

# ──────────────────────────────────────────────
# Feature schema (must match zeek_ingest.py v2 output)
# ──────────────────────────────────────────────

# All numeric features fed to the ML models
FEATURE_COLUMNS = [
    "id.orig_p",
    "id.resp_p",
    "orig_bytes",
    "resp_bytes",
    "exfiltration_ratio",
    "syn_flag_count",
    "ack_flag_count",
    "syn_ack_ratio",
    "flow_rate",
]

# Metadata columns (not fed to the model, but kept for context)
METADATA_COLUMNS = ["id.orig_h", "id.resp_h", "proto"]

MODEL_OUT = os.path.join(os.path.dirname(__file__), "ddos_dual_engine_model.joblib")
TRAIN_FRACTION = 0.7
CLASSIFIER_CONFIDENCE_THRESHOLD = 0.5
ANOMALY_SCORE_THRESHOLD = 0.7


# ──────────────────────────────────────────────
# Synthetic data generator with REALISTIC noise
# ──────────────────────────────────────────────

def generate_synthetic_dataset(n_samples: int = 8000) -> pd.DataFrame:
    """Generate a synthetic labeled Zeek flow dataset with realistic noise.

    Unlike the v1 generator, this version:
      - Adds Gaussian noise to all features to prevent 100% memorization
      - Includes overlapping feature ranges between classes
      - Models TCP flag behavior via the Zeek `history` column semantics
      - Includes the flow_rate temporal feature
    """
    rng = np.random.default_rng(42)
    records = []

    class_distribution = {
        "benign": int(n_samples * 0.55),
        "ddos_syn_flood": int(n_samples * 0.15),
        "ddos_volumetric": int(n_samples * 0.10),
        "port_scan": int(n_samples * 0.10),
        "exfiltration": int(n_samples * 0.10),
    }

    for label, count in class_distribution.items():
        for _ in range(count):
            if label == "benign":
                # Normal traffic: balanced SYN/ACK, moderate bytes, low flow_rate
                syn_count = int(rng.integers(1, 3))  # 1-2 SYNs (handshake)
                ack_count = int(rng.integers(1, 4))  # 1-3 ACKs (handshake + data)
                rec = {
                    "id.orig_h": f"10.0.{rng.integers(1, 10)}.{rng.integers(1, 254)}",
                    "id.resp_h": f"192.168.1.{rng.integers(1, 20)}",
                    "id.orig_p": int(rng.integers(1024, 65535)),
                    "id.resp_p": int(rng.choice([80, 443, 53, 22, 8080, 3306])),
                    "proto": rng.choice(["tcp", "udp"]),
                    "orig_bytes": int(rng.integers(100, 8000) + rng.normal(0, 500)),
                    "resp_bytes": int(rng.integers(200, 50000) + rng.normal(0, 2000)),
                    "syn_flag_count": syn_count,
                    "ack_flag_count": ack_count,
                    "flow_rate": int(rng.integers(1, 15)),  # Low flow rate
                }
            elif label == "ddos_syn_flood":
                # SYN flood: MANY SYNs, almost ZERO ACKs, tiny packets, high flow_rate
                syn_count = int(rng.integers(3, 8))   # Multiple SYN attempts
                ack_count = int(rng.integers(0, 1))    # No handshake completion
                rec = {
                    "id.orig_h": f"185.{rng.integers(1, 254)}.{rng.integers(1, 254)}.{rng.integers(1, 254)}",
                    "id.resp_h": "192.168.1.1",
                    "id.orig_p": int(rng.integers(1024, 65535)),
                    "id.resp_p": int(rng.choice([80, 443])),
                    "proto": "tcp",
                    "orig_bytes": int(rng.integers(40, 120) + rng.normal(0, 15)),
                    "resp_bytes": int(rng.integers(0, 44) + abs(rng.normal(0, 10))),
                    "syn_flag_count": syn_count,
                    "ack_flag_count": ack_count,
                    "flow_rate": int(rng.integers(80, 500)),  # Very high
                }
            elif label == "ddos_volumetric":
                # Volumetric flood: large payloads, moderate SYNs, very high flow_rate
                syn_count = int(rng.integers(1, 3))
                ack_count = int(rng.integers(0, 2))
                rec = {
                    "id.orig_h": f"91.{rng.integers(1, 254)}.{rng.integers(1, 254)}.{rng.integers(1, 254)}",
                    "id.resp_h": "192.168.1.1",
                    "id.orig_p": int(rng.integers(1024, 65535)),
                    "id.resp_p": int(rng.choice([80, 443, 53])),
                    "proto": rng.choice(["tcp", "udp"]),
                    "orig_bytes": int(rng.integers(50000, 500000) + rng.normal(0, 20000)),
                    "resp_bytes": int(rng.integers(0, 500) + abs(rng.normal(0, 100))),
                    "syn_flag_count": syn_count,
                    "ack_flag_count": ack_count,
                    "flow_rate": int(rng.integers(50, 300)),  # High
                }
            elif label == "port_scan":
                # Port scan: tiny probe packets, low SYN/ACK, moderate flow_rate, random ports
                syn_count = int(rng.integers(1, 2))
                ack_count = int(rng.integers(0, 1))
                rec = {
                    "id.orig_h": f"10.99.{rng.integers(1, 254)}.{rng.integers(1, 254)}",
                    "id.resp_h": f"192.168.1.{rng.integers(1, 254)}",
                    "id.orig_p": int(rng.integers(1024, 65535)),
                    "id.resp_p": int(rng.integers(1, 65535)),  # Random target ports
                    "proto": "tcp",
                    "orig_bytes": int(rng.integers(40, 80) + rng.normal(0, 10)),
                    "resp_bytes": int(rng.integers(0, 60) + abs(rng.normal(0, 15))),
                    "syn_flag_count": syn_count,
                    "ack_flag_count": ack_count,
                    "flow_rate": int(rng.integers(20, 80)),  # Moderate
                }
            else:  # exfiltration
                # Exfiltration: huge uploads, tiny responses, normal SYN/ACK, low flow_rate
                syn_count = int(rng.integers(1, 3))
                ack_count = int(rng.integers(1, 4))
                rec = {
                    "id.orig_h": f"10.0.{rng.integers(1, 10)}.{rng.integers(100, 200)}",
                    "id.resp_h": f"45.{rng.integers(1, 254)}.{rng.integers(1, 254)}.{rng.integers(1, 254)}",
                    "id.orig_p": int(rng.integers(1024, 65535)),
                    "id.resp_p": int(rng.choice([443, 8443, 4443, 53])),
                    "proto": "tcp",
                    "orig_bytes": int(rng.integers(100000, 5000000) + rng.normal(0, 50000)),
                    "resp_bytes": int(rng.integers(100, 2000) + abs(rng.normal(0, 200))),
                    "syn_flag_count": syn_count,
                    "ack_flag_count": ack_count,
                    "flow_rate": int(rng.integers(1, 10)),  # Low (stealth)
                }

            # Clamp negatives from noise
            rec["orig_bytes"] = max(0, rec["orig_bytes"])
            rec["resp_bytes"] = max(0, rec["resp_bytes"])
            rec["syn_flag_count"] = max(0, rec["syn_flag_count"])
            rec["ack_flag_count"] = max(0, rec["ack_flag_count"])
            rec["flow_rate"] = max(1, rec["flow_rate"])

            rec["exfiltration_ratio"] = rec["orig_bytes"] / (rec["resp_bytes"] + 1)
            rec["syn_ack_ratio"] = rec["syn_flag_count"] / (rec["ack_flag_count"] + 1)
            rec["Label"] = label
            records.append(rec)

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"Generated synthetic dataset: {len(df)} rows")
    print(f"Class distribution:\n{df['Label'].value_counts()}")
    return df


# ──────────────────────────────────────────────
# Training pipeline
# ──────────────────────────────────────────────

def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Clean the dataset: handle infinities, NaN, and duplicates."""
    df = df.replace([np.inf, -np.inf], np.nan)
    n_before = len(df)
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].fillna(0)
    df = df.drop_duplicates()
    print(f"Cleaning: {n_before} -> {len(df)} rows after dedup")
    return df


def temporal_split(df: pd.DataFrame, train_fraction: float = TRAIN_FRACTION):
    """Split dataset preserving class balance."""
    train_parts, test_parts = [], []
    for label, group in df.groupby("Label"):
        group = group.sample(frac=1, random_state=42).reset_index(drop=True)
        cutoff = int(len(group) * train_fraction)
        train_parts.append(group.iloc[:cutoff])
        test_parts.append(group.iloc[cutoff:])
    train_df = pd.concat(train_parts).reset_index(drop=True)
    test_df = pd.concat(test_parts).reset_index(drop=True)
    print(f"\nSplit: {len(train_df)} train / {len(test_df)} test")
    print(f"Train labels:\n{train_df['Label'].value_counts()}")
    print(f"Test labels:\n{test_df['Label'].value_counts()}")
    return train_df, test_df


def train(input_csv: str | None = None) -> None:
    """Train the dual-engine model and save the .joblib bundle."""

    # Load or generate data
    if input_csv and os.path.exists(input_csv):
        print(f"Loading labeled Zeek features from '{input_csv}'...")
        df = pd.read_csv(input_csv)
        if "Label" not in df.columns:
            print("ERROR: CSV must have a 'Label' column for supervised training.")
            sys.exit(1)
    else:
        if input_csv:
            print(f"WARNING: '{input_csv}' not found. Generating synthetic dataset.")
        else:
            print("No input CSV specified. Generating synthetic dataset.")
        df = generate_synthetic_dataset()

    # Ensure all feature columns exist
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            print(f"WARNING: Column '{col}' missing, initializing with 0.")
            df[col] = 0

    # Recompute derived features if missing
    if "exfiltration_ratio" not in df.columns or df["exfiltration_ratio"].isna().all():
        df["exfiltration_ratio"] = df["orig_bytes"] / (df["resp_bytes"] + 1.0)
    if "syn_ack_ratio" not in df.columns or df["syn_ack_ratio"].isna().all():
        df["syn_ack_ratio"] = df["syn_flag_count"] / (df["ack_flag_count"] + 1.0)

    df = clean(df)
    feature_cols = FEATURE_COLUMNS

    train_df, test_df = temporal_split(df)

    X_train_raw = train_df[feature_cols].copy()
    X_test_raw = test_df[feature_cols].copy()
    y_train = train_df["Label"]
    y_test = test_df["Label"]

    # Scale
    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    # Stage 1: Isolation Forest (trained on benign only)
    print("\nTraining IsolationForest (Stage 1: anomaly detector)...")
    benign_mask = (y_train == "benign").values
    iso_model = IsolationForest(contamination=0.05, random_state=42)
    iso_model.fit(X_train[benign_mask])

    raw_scores_benign = -iso_model.score_samples(X_train[benign_mask])
    score_min = float(raw_scores_benign.min())
    score_max = float(raw_scores_benign.max())

    # Stage 2: Random Forest classifier
    print("Training RandomForest (Stage 2: sub-type classifier)...")
    clf = RandomForestClassifier(
        n_estimators=200, class_weight="balanced", random_state=42
    )
    clf.fit(X_train, y_train)

    # Evaluation
    print("\n--- Classification Report (held-out test set) ---")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    print("Confusion matrix (rows=true, cols=predicted):")
    cm = pd.DataFrame(
        confusion_matrix(y_test, y_pred, labels=clf.classes_),
        index=clf.classes_,
        columns=clf.classes_,
    )
    print(cm)

    # Compute benign baseline stats for z-score explainability
    benign_mean = X_train_raw[benign_mask].mean()
    benign_std = X_train_raw[benign_mask].std().replace(0, 1e-9)

    # Save bundle
    bundle = {
        "iso_model": iso_model,
        "clf": clf,
        "scaler": scaler,
        "feature_cols": feature_cols,
        "score_min": score_min,
        "score_max": score_max,
        "benign_mean": benign_mean,
        "benign_std": benign_std,
    }
    joblib.dump(bundle, MODEL_OUT)
    print(f"\nModel bundle saved to {MODEL_OUT}")
    print(f"Feature columns ({len(feature_cols)}): {feature_cols}")
    print(f"Classes: {list(clf.classes_)}")


def main():
    parser = argparse.ArgumentParser(
        description="Train dual-engine DDoS detector on Zeek flow features (v2)."
    )
    parser.add_argument(
        "-i", "--input",
        dest="input_csv",
        default=None,
        help="Path to labeled zeek_features_v2.csv (with Label column). "
             "If omitted, generates synthetic data.",
    )
    args = parser.parse_args()
    train(args.input_csv)


if __name__ == "__main__":
    main()
