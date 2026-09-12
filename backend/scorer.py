"""
scorer.py — In-Memory Scoring Engine for Zeek Flow Features (v2)

Loads the dual-engine model bundle (IsolationForest + RandomForest) trained
on Zeek conn.log features and scores individual flows.

Feature Schema (9 numeric features):
    id.orig_p, id.resp_p, orig_bytes, resp_bytes, exfiltration_ratio,
    syn_flag_count, ack_flag_count, syn_ack_ratio, flow_rate

Metadata (not fed to model):
    id.orig_h, id.resp_h, proto
"""

import os

import joblib
import numpy as np
import pandas as pd
import shap

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ddos_dual_engine_model.joblib")
CLASSIFIER_CONFIDENCE_THRESHOLD = 0.5
ANOMALY_SCORE_THRESHOLD = 0.55

# ── Heuristic thresholds ────────────────────────────────────────────
# These catch unambiguous attack patterns that the ML model might miss.
# Each threshold is derived from the Zeek conn.log feature semantics.

# SYN flood: high syn_ack_ratio means many SYNs without completing handshake
SYN_FLOOD_RATIO_THRESHOLD = 3.0

# Volumetric flood: high flow_rate means massive burst of connections
VOLUMETRIC_FLOW_RATE_THRESHOLD = 100

# Data exfiltration: high exfiltration_ratio means huge uploads vs tiny responses
EXFILTRATION_RATIO_THRESHOLD = 50.0

print("Loading dual-engine bundle (Zeek v2 schema)...")
bundle = joblib.load(MODEL_PATH)

iso_model = bundle["iso_model"]
clf = bundle["clf"]
scaler = bundle["scaler"]
feature_cols = bundle["feature_cols"]
score_min = bundle["score_min"]
score_max = bundle["score_max"]
benign_mean = bundle["benign_mean"]
benign_std = bundle["benign_std"]

# Pre-compute SHAP explainer once to ensure fast inference per flow
print("Initializing TreeSHAP explainer...")
explainer = shap.TreeExplainer(clf)


def normalize_anomaly(raw_score: float) -> float:
    return float(
        np.clip((raw_score - score_min) / (score_max - score_min + 1e-9), 0, 1)
    )


def top_shap_features(x_scaled, predicted_class: str, n: int = 3) -> dict:
    shap_values = explainer.shap_values(x_scaled)
    class_idx = list(clf.classes_).index(predicted_class)
    vals = (
        shap_values[class_idx][0]
        if isinstance(shap_values, list)
        else shap_values[0, :, class_idx]
    )
    contributions = dict(zip(feature_cols, vals))
    top = sorted(
        contributions.items(), key=lambda kv: abs(kv[1]), reverse=True
    )[:n]
    return {k: round(float(v), 4) for k, v in top}


def top_zscore_features(feature_dict: dict, n: int = 3) -> dict:
    z = {
        f: abs((feature_dict[f] - benign_mean[f]) / benign_std[f])
        for f in feature_cols
    }
    top = sorted(z.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return {k: round(float(v), 2) for k, v in top}


def score_window(feature_dict: dict) -> dict:
    """Evaluates a single Zeek flow dict and returns a structured alert verdict.

    Expected keys:
        Numeric (model input): id.orig_p, id.resp_p, orig_bytes, resp_bytes,
                               exfiltration_ratio, syn_flag_count, ack_flag_count,
                               syn_ack_ratio, flow_rate
        Metadata: id.orig_h (source IP), id.resp_h (dest IP), proto
    """
    x_raw = pd.DataFrame([{f: feature_dict.get(f, 0) for f in feature_cols}])
    x_scaled = scaler.transform(x_raw)

    anomaly_score = normalize_anomaly(-iso_model.score_samples(x_scaled)[0])
    proba = clf.predict_proba(x_scaled)[0]
    predicted_class = clf.classes_[np.argmax(proba)]
    class_confidence = float(np.max(proba))

    classifier_fired = (
        predicted_class != "benign"
        and class_confidence > CLASSIFIER_CONFIDENCE_THRESHOLD
    )
    anomaly_fired = anomaly_score > ANOMALY_SCORE_THRESHOLD

    # ── Heuristic overrides from Zeek features ──────────────────────

    # SYN flood: syn_ack_ratio > threshold AND high flow_rate
    syn_ack_ratio = feature_dict.get("syn_ack_ratio", 0)
    flow_rate = feature_dict.get("flow_rate", 1)
    syn_flood_fired = (
        syn_ack_ratio > SYN_FLOOD_RATIO_THRESHOLD
        and flow_rate > 30
    )

    # Volumetric flood: extremely high flow_rate
    volumetric_fired = flow_rate > VOLUMETRIC_FLOW_RATE_THRESHOLD

    # Data exfiltration: high exfiltration ratio
    exfil_ratio = feature_dict.get("exfiltration_ratio", 0)
    exfiltration_fired = exfil_ratio > EXFILTRATION_RATIO_THRESHOLD

    # Extract metadata
    src_ip = feature_dict.get("id.orig_h", "unknown_ip")
    dst_ip = feature_dict.get("id.resp_h", "unknown_ip")
    proto = feature_dict.get("proto", "tcp")
    timestamp = feature_dict.get("ts", "unknown_time")

    base_response = {
        "flow_id": f"{src_ip}-{dst_ip}-{feature_dict.get('id.orig_p', 0)}-{feature_dict.get('id.resp_p', 0)}",
        "timestamp": str(timestamp),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "anomaly_score": round(anomaly_score, 3),
        "classifier_probability": round(class_confidence, 3),
    }

    # ── Priority cascade: heuristic overrides first, then ML ────────

    if syn_flood_fired:
        # SYN flood detected via Zeek history-derived flag counts.
        # Confidence 0.99 (not 1.0) to avoid flat-line on UI charts.
        threat_class = "ddos_syn_flood"
        confidence = 0.99
        severity = "critical"
        evidence = {
            "syn_flag_count": int(feature_dict.get("syn_flag_count", 0)),
            "ack_flag_count": int(feature_dict.get("ack_flag_count", 0)),
            "syn_ack_ratio": round(float(syn_ack_ratio), 3),
            "flow_rate": int(flow_rate),
        }

    elif volumetric_fired:
        threat_class = "ddos_volumetric"
        confidence = 0.97
        severity = "critical"
        evidence = {
            "flow_rate": int(flow_rate),
            "orig_bytes": int(feature_dict.get("orig_bytes", 0)),
            "resp_bytes": int(feature_dict.get("resp_bytes", 0)),
        }

    elif exfiltration_fired:
        threat_class = "exfiltration"
        confidence = 0.95
        severity = "critical"
        evidence = {
            "exfiltration_ratio": round(float(exfil_ratio), 2),
            "orig_bytes": int(feature_dict.get("orig_bytes", 0)),
            "resp_bytes": int(feature_dict.get("resp_bytes", 0)),
        }

    elif classifier_fired and anomaly_fired:
        threat_class = predicted_class
        confidence = max(class_confidence, anomaly_score)
        severity = "critical"
        evidence = top_shap_features(x_scaled, predicted_class)
    elif classifier_fired:
        threat_class = predicted_class
        confidence = class_confidence
        severity = "high"
        evidence = top_shap_features(x_scaled, predicted_class)
    elif anomaly_fired:
        threat_class = "ddos_unknown_variant"
        confidence = anomaly_score
        severity = "medium"
        evidence = top_zscore_features(feature_dict)
    else:
        # ── Benign verdict ──
        base_response["is_alert"] = False
        return base_response

    # ── Alert verdict ──
    base_response.update({
        "is_alert": True,
        "threat_class": threat_class,
        "confidence": round(float(confidence), 3),
        "severity": severity,
        "evidence": evidence,
    })
    return base_response


if __name__ == "__main__":
    print(f"Loaded successfully with {len(feature_cols)} features:")
    print(feature_cols)

    # -- Sanity check 1: Benign flow --
    print("\n-- Sanity check 1: Benign Zeek flow --")
    synthetic_benign = {
        "id.orig_h": "10.0.1.50",
        "id.resp_h": "192.168.1.1",
        "id.orig_p": 54321,
        "id.resp_p": 443,
        "proto": "tcp",
        "orig_bytes": 1200,
        "resp_bytes": 8500,
        "exfiltration_ratio": 1200 / (8500 + 1),
        "syn_flag_count": 1,
        "ack_flag_count": 2,
        "syn_ack_ratio": 1 / (2 + 1),
        "flow_rate": 3,
    }
    verdict = score_window(synthetic_benign)
    print(f"  is_alert={verdict.get('is_alert')} (expected: False)")
    print(f"  {verdict}")

    # -- Sanity check 2: SYN flood --
    print("\n-- Sanity check 2: SYN flood --")
    syn_flood = {
        "id.orig_h": "185.14.72.19",
        "id.resp_h": "192.168.1.1",
        "id.orig_p": 12345,
        "id.resp_p": 80,
        "proto": "tcp",
        "orig_bytes": 60,
        "resp_bytes": 0,
        "exfiltration_ratio": 60 / (0 + 1),
        "syn_flag_count": 6,
        "ack_flag_count": 0,
        "syn_ack_ratio": 6.0,
        "flow_rate": 250,
    }
    verdict = score_window(syn_flood)
    print(f"  is_alert={verdict.get('is_alert')} (expected: True)")
    print(f"  threat_class={verdict.get('threat_class')} (expected: ddos_syn_flood)")
    print(f"  {verdict}")

    # -- Sanity check 3: Volumetric flood --
    print("\n-- Sanity check 3: Volumetric flood --")
    volumetric = {
        "id.orig_h": "91.204.18.77",
        "id.resp_h": "192.168.1.1",
        "id.orig_p": 9999,
        "id.resp_p": 443,
        "proto": "udp",
        "orig_bytes": 200000,
        "resp_bytes": 100,
        "exfiltration_ratio": 200000 / 101,
        "syn_flag_count": 1,
        "ack_flag_count": 0,
        "syn_ack_ratio": 1.0,
        "flow_rate": 180,
    }
    verdict = score_window(volumetric)
    print(f"  is_alert={verdict.get('is_alert')} (expected: True)")
    print(f"  threat_class={verdict.get('threat_class')} (expected: ddos_volumetric)")
    print(f"  {verdict}")