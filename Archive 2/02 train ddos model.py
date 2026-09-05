"""
Step 2: Clean, split, scale, and train the dual-engine DDoS detector
(Isolation Forest + Random Forest) on windowed_features.csv,
with TreeSHAP / z-score explainability and an ensemble decision function.

Output: ddos_dual_engine_model.joblib
"""

import numpy as np
import pandas as pd
import joblib
import shap
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import classification_report, confusion_matrix

INPUT_CSV = "windowed_features.csv"
MODEL_OUT = "ddos_dual_engine_model.joblib"

FEATURE_COLUMNS = [
    "flow_rate", "packet_rate", "fwd_bwd_ratio", "unique_src_count",
    "src_ip_entropy", "syn_flag_sum", "ack_flag_sum", "syn_ack_ratio",
    "avg_packet_size", "packet_size_std", "unique_dst_ports",
]
METADATA_COLUMNS = ["Dst_IP", "Window_Start"]

CLASSIFIER_CONFIDENCE_THRESHOLD = 0.5
ANOMALY_SCORE_THRESHOLD = 0.7
CORRELATION_DROP_THRESHOLD = 0.95
TRAIN_FRACTION = 0.7  


def clean(df):
    df = df.replace([np.inf, -np.inf], np.nan)
    n_before = len(df)
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].fillna(0)
    df = df.drop_duplicates()
    print(f"Cleaning: {n_before} -> {len(df)} rows after dedup")
    return df


def quick_eda(df):
    print("\n--- Class balance ---")
    print(df["Label"].value_counts())

    print("\n--- Correlation matrix (features) ---")
    corr = df[FEATURE_COLUMNS].corr()
    print(corr.round(2))
    return corr

def drop_correlated(corr, threshold=CORRELATION_DROP_THRESHOLD):
    to_drop = set()
    cols = corr.columns
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            if abs(corr.iloc[i, j]) > threshold:
                to_drop.add(cols[j])  
    kept = [c for c in FEATURE_COLUMNS if c not in to_drop]
    if to_drop:
        print(f"\nDropping highly correlated features: {to_drop}")
    else:
        print("\nNo features exceeded the correlation threshold — keeping all.")
    return kept


def temporal_split(df, train_fraction=TRAIN_FRACTION):
    train_parts, test_parts = [], []
    for label, group in df.groupby("Label"):
        group = group.sort_values("Window_Start")
        cutoff = int(len(group) * train_fraction)
        train_parts.append(group.iloc[:cutoff])
        test_parts.append(group.iloc[cutoff:])
    train_df = pd.concat(train_parts).reset_index(drop=True)
    test_df = pd.concat(test_parts).reset_index(drop=True)
    print(f"\nTemporal split: {len(train_df)} train / {len(test_df)} test")
    print("Train label distribution:\n", train_df["Label"].value_counts())
    print("Test label distribution:\n", test_df["Label"].value_counts())
    return train_df, test_df


def main():
    print("Loading windowed features...")
    df = pd.read_csv(INPUT_CSV, parse_dates=["Window_Start"])

    df = clean(df)
    corr = quick_eda(df)
    feature_cols = drop_correlated(corr)

    train_df, test_df = temporal_split(df)

    X_train_raw = train_df[feature_cols]
    X_test_raw = test_df[feature_cols]
    y_train = train_df["Label"]
    y_test = test_df["Label"]

    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)


    print("\nTraining Isolation Forest (Stage 1: zero-day anomaly detector)...")
    benign_mask_train = (y_train == "benign").values
    iso_model = IsolationForest(contamination=0.05, random_state=42)
    iso_model.fit(X_train[benign_mask_train])

    raw_scores_benign = -iso_model.score_samples(X_train[benign_mask_train])
    score_min, score_max = raw_scores_benign.min(), raw_scores_benign.max()

    def normalize_anomaly(raw_score):
        return float(np.clip((raw_score - score_min) / (score_max - score_min + 1e-9), 0, 1))


    print("Training Random Forest (Stage 2: sub-type classifier)...")
    clf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42)
    clf.fit(X_train, y_train)

    print("\n--- Classification report (held-out test set) ---")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    print("Confusion matrix (rows=true, cols=predicted):")
    print(pd.DataFrame(confusion_matrix(y_test, y_pred, labels=clf.classes_),
                        index=clf.classes_, columns=clf.classes_))

    explainer = shap.TreeExplainer(clf)
    benign_mean = X_train_raw[benign_mask_train].mean()
    benign_std = X_train_raw[benign_mask_train].std().replace(0, 1e-9)

    def top_shap_features(x_row_scaled, predicted_class, n=3):
        shap_values = explainer.shap_values(x_row_scaled)
        class_idx = list(clf.classes_).index(predicted_class)
        vals = shap_values[class_idx][0] if isinstance(shap_values, list) else shap_values[0, :, class_idx]
        contributions = dict(zip(feature_cols, vals))
        top = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)[:n]
        return {k: round(float(v), 4) for k, v in top}

    def top_zscore_features(feature_dict, n=3):
        z = {f: abs((feature_dict[f] - benign_mean[f]) / benign_std[f]) for f in feature_cols}
        top = sorted(z.items(), key=lambda kv: kv[1], reverse=True)[:n]
        return {k: round(float(v), 2) for k, v in top}

    def score_window(feature_dict: dict) -> dict:
        x_raw = pd.DataFrame([{f: feature_dict[f] for f in feature_cols}])
        x_scaled = scaler.transform(x_raw)

        anomaly_score = normalize_anomaly(-iso_model.score_samples(x_scaled)[0])
        proba = clf.predict_proba(x_scaled)[0]
        predicted_class = clf.classes_[np.argmax(proba)]
        class_confidence = float(np.max(proba))

        classifier_fired = predicted_class != "benign" and class_confidence > CLASSIFIER_CONFIDENCE_THRESHOLD
        anomaly_fired = anomaly_score > ANOMALY_SCORE_THRESHOLD

        if classifier_fired and anomaly_fired:
            threat_class, confidence, severity = predicted_class, max(class_confidence, anomaly_score), "critical"
            evidence = top_shap_features(x_scaled, predicted_class)
        elif classifier_fired:
            threat_class, confidence, severity = predicted_class, class_confidence, "high"
            evidence = top_shap_features(x_scaled, predicted_class)
        elif anomaly_fired:
            threat_class, confidence, severity = "ddos_unknown_variant", anomaly_score, "medium"
            evidence = top_zscore_features(feature_dict)
        else:
            return {"is_alert": False}

        return {
            "is_alert": True,
            "threat_class": threat_class,
            "confidence_score": round(confidence, 3),
            "severity": severity,
            "supporting_evidence": evidence,
            "anomaly_score": round(anomaly_score, 3),
            "classifier_probability": round(class_confidence, 3),
        }


    print("\n--- Sanity check: one row per class ---")
    for label in test_df["Label"].unique():
        row = test_df[test_df["Label"] == label].iloc[0]
        fd = {f: row[f] for f in feature_cols}
        result = score_window(fd)
        print(f"True label: {row['Label']}  ->  {result}")


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


if __name__ == "__main__":
    main()