"""Train a lightweight threat classifier for the controlled playback dataset."""
from __future__ import annotations
import argparse, csv, pickle
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

FEATURES = ["target_port", "packet_size", "payload_entropy", "protocol_tcp", "protocol_udp"]

def featurize(row: dict) -> list[float]:
    return [int(row["target_port"]) / 65535, int(row["packet_size"]) / 2500, float(row["payload_entropy"]) / 8, int(row["protocol"] == "TCP"), int(row["protocol"] == "UDP")]

def read_rows(path: Path) -> list[dict]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as stream: return list(csv.DictReader(stream))
    import json
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def train(data_path: Path, model_path: Path) -> None:
    rows = read_rows(data_path)
    X = np.array([featurize(row) for row in rows]); y = np.array([int(row.get("label", row.get("attack_classification") != "Normal")) for row in rows])
    model = RandomForestClassifier(n_estimators=120, max_depth=10, class_weight="balanced", random_state=42, n_jobs=-1).fit(X, y)
    predictions = model.predict(X)
    print(classification_report(y, predictions, target_names=["Normal", "Threat"], zero_division=0))
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with model_path.open("wb") as stream: pickle.dump({"model": model, "features": FEATURES, "classes": ["Normal", "Threat"]}, stream)
    print(f"Saved model to {model_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--data", type=Path, default=Path("backend/data/playback.csv")); parser.add_argument("--output", type=Path, default=Path("backend/models/threat_detector.pkl")); args = parser.parse_args(); train(args.data, args.output)
