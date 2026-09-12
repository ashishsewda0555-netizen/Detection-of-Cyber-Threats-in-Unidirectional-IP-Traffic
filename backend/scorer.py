"""
scorer.py — In-Memory Scoring Engine for Unified Pipeline

Loads the dual-engine model bundle (IsolationForest + RandomForest) trained
on the Unified (Scapy + Zeek) features and scores individual flows.

Schema (14 numeric features):
    flow_rate, packet_rate, fwd_bwd_ratio, unique_src_count, src_ip_entropy,
    syn_flag_sum, ack_flag_sum, syn_ack_ratio, avg_packet_size, packet_size_std,
    unique_dst_ports, orig_bytes, resp_bytes, exfiltration_ratio
"""

import os
import joblib
import numpy as np
import pandas as pd
import shap

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ddos_unified_model.joblib")
CLASSIFIER_CONFIDENCE_THRESHOLD = 0.5
ANOMALY_SCORE_THRESHOLD = 0.55

# Heuristic overrides (combining Scapy and Zeek strengths)
SYN_FLOOD_RATIO_THRESHOLD = 3.0
VOLUMETRIC_FLOW_RATE_THRESHOLD = 100
EXFILTRATION_RATIO_THRESHOLD = 50.0
PORT_SCAN_DST_PORTS_THRESHOLD = 20

print("Loading dual-engine bundle (Unified schema)...")
bundle = joblib.load(MODEL_PATH)

iso_model = bundle["iso_model"]
clf = bundle["clf"]
scaler = bundle["scaler"]
feature_cols = bundle["feature_cols"]
score_min = bundle["score_min"]
score_max = bundle["score_max"]
benign_mean = bundle["benign_mean"]
benign_std = bundle["benign_std"]

print("Initializing TreeSHAP explainer...")
explainer = shap.TreeExplainer(clf)


def normalize_anomaly(raw_score: float) -> float:
    return float(np.clip((raw_score - score_min) / (score_max - score_min + 1e-9), 0, 1))

def top_shap_features(x_scaled, predicted_class: str, n: int = 3) -> dict:
    shap_values = explainer.shap_values(x_scaled)
    class_idx = list(clf.classes_).index(predicted_class)
    vals = (
        shap_values[class_idx][0]
        if isinstance(shap_values, list)
        else shap_values[0, :, class_idx]
    )
    contributions = dict(zip(feature_cols, vals))
    top = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)[:n]
    return {k: round(float(v), 4) for k, v in top}

def top_zscore_features(feature_dict: dict, n: int = 3) -> dict:
    z = {f: abs((feature_dict[f] - benign_mean[f]) / benign_std[f]) for f in feature_cols}
    top = sorted(z.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return {k: round(float(v), 2) for k, v in top}


def score_window(feature_dict: dict) -> dict:
    x_raw = pd.DataFrame([{f: feature_dict.get(f, 0) for f in feature_cols}])
    x_scaled = scaler.transform(x_raw)

    anomaly_score = normalize_anomaly(-iso_model.score_samples(x_scaled)[0])
    proba = clf.predict_proba(x_scaled)[0]
    predicted_class = clf.classes_[np.argmax(proba)]
    class_confidence = float(np.max(proba))

    classifier_fired = (predicted_class != "benign" and class_confidence > CLASSIFIER_CONFIDENCE_THRESHOLD)
    anomaly_fired = anomaly_score > ANOMALY_SCORE_THRESHOLD

    # Extract heuristics
    syn_ack_ratio = feature_dict.get("syn_ack_ratio", 0)
    flow_rate = feature_dict.get("flow_rate", 1)
    exfil_ratio = feature_dict.get("exfiltration_ratio", 0)
    unique_dst_ports = feature_dict.get("unique_dst_ports", 0)

    syn_flood_fired = (syn_ack_ratio > SYN_FLOOD_RATIO_THRESHOLD and flow_rate > 30)
    volumetric_fired = flow_rate > VOLUMETRIC_FLOW_RATE_THRESHOLD
    exfiltration_fired = exfil_ratio > EXFILTRATION_RATIO_THRESHOLD
    port_scan_fired = unique_dst_ports >= PORT_SCAN_DST_PORTS_THRESHOLD

    # Metadata
    src_ip = feature_dict.get("id.orig_h", feature_dict.get("Src_IP", "unknown_ip"))
    dst_ip = feature_dict.get("id.resp_h", feature_dict.get("Dst_IP", "unknown_ip"))
    proto = feature_dict.get("proto", "tcp")
    timestamp = feature_dict.get("Window_Start", "unknown_time")

    base_response = {
        "flow_id": f"{src_ip}-{dst_ip}-{feature_dict.get('id.orig_p', 0)}-{feature_dict.get('id.resp_p', 0)}",
        "timestamp": str(timestamp),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "anomaly_score": round(anomaly_score, 3),
        "classifier_probability": round(class_confidence, 3),
    }

    # Priority cascade
    if port_scan_fired:
        threat_class = "port_scan"
        confidence = 1.0
        severity = "high"
        evidence = {"unique_dst_ports": int(unique_dst_ports)}
    elif syn_flood_fired:
        threat_class = "ddos_syn_flood"
        confidence = 0.99
        severity = "critical"
        evidence = {
            "syn_ack_ratio": round(float(syn_ack_ratio), 3),
            "flow_rate": int(flow_rate),
        }
    elif volumetric_fired:
        threat_class = "ddos_volumetric"
        confidence = 0.97
        severity = "critical"
        evidence = {"flow_rate": int(flow_rate)}
    elif exfiltration_fired:
        threat_class = "exfiltration"
        confidence = 0.95
        severity = "critical"
        evidence = {"exfiltration_ratio": round(float(exfil_ratio), 2)}
    elif classifier_fired and anomaly_fired:
        threat_class = predicted_class
        confidence = max(class_confidence, anomaly_score)
        severity = "critical" if class_confidence > 0.85 else "warning"
        evidence = top_shap_features(x_scaled, predicted_class)
    elif classifier_fired:
        threat_class = predicted_class
        confidence = class_confidence
        severity = "critical" if class_confidence > 0.85 else "warning"
        evidence = top_shap_features(x_scaled, predicted_class)
    elif anomaly_fired:
        threat_class = "ddos_unknown_variant"
        confidence = anomaly_score
        severity = "medium"
        evidence = top_zscore_features(feature_dict)
    else:
        base_response["is_alert"] = False
        return base_response

    base_response.update({
        "is_alert": True,
        "threat_class": threat_class,
        "confidence": round(float(confidence), 3),
        "severity": severity,
        "evidence": evidence,
    })
    return base_response

if __name__ == "__main__":
    print(f"Loaded successfully with {len(feature_cols)} features")
    
    # -- Sanity check: Exfiltration --
    print("\n-- Sanity check: Exfiltration (Unified) --")
    synthetic_exfil = {
        "id.orig_h": "10.0.1.50",
        "id.resp_h": "192.168.1.1",
        "id.orig_p": 54321,
        "id.resp_p": 443,
        "proto": "tcp",
        "flow_rate": 5.0,
        "packet_rate": 20.0,
        "fwd_bwd_ratio": 15.0,
        "unique_src_count": 1,
        "src_ip_entropy": 0.0,
        "syn_flag_sum": 2,
        "ack_flag_sum": 50,
        "syn_ack_ratio": 0.03,
        "avg_packet_size": 1400.0,
        "packet_size_std": 50.0,
        "unique_dst_ports": 1,
        "orig_bytes": 1000000,
        "resp_bytes": 200,
        "exfiltration_ratio": 1000000 / 201,
    }
    verdict = score_window(synthetic_exfil)
    print(f"  is_alert={verdict.get('is_alert')} (expected: True)")
    print(f"  threat_class={verdict.get('threat_class')} (expected: exfiltration)")
    print(f"  {verdict}")