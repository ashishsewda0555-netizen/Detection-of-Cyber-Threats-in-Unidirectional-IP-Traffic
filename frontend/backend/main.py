"""FastAPI playback engine for the SIH26145 crash-proof demo."""
from __future__ import annotations
import asyncio, csv, json, pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "playback.csv"
MODEL_PATH = ROOT / "models" / "threat_detector.pkl"
app = FastAPI(title="Signal Room Playback API", version="1.1.0", description="Controlled sequential replay of packet metadata for SIH26145.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
try:
    with MODEL_PATH.open("rb") as stream: MODEL_BUNDLE = pickle.load(stream)
except FileNotFoundError: MODEL_BUNDLE = None

class Packet(BaseModel):
    source_ip: str; target_port: int; packet_size: int; protocol: str; payload_entropy: float

def rows() -> list[dict]:
    if not DATA_PATH.exists(): raise HTTPException(503, "Playback dataset missing. Run backend/generate_pcap.py first.")
    with DATA_PATH.open(newline="", encoding="utf-8") as stream: return list(csv.DictReader(stream))

def features(row: dict) -> list[float]:
    return [int(row["target_port"]) / 65535, int(row["packet_size"]) / 2500, float(row["payload_entropy"]) / 8, int(row["protocol"] == "TCP"), int(row["protocol"] == "UDP")]

def analyze(row: dict) -> dict:
    is_threat = row.get("attack_classification", "Normal") != "Normal"
    confidence = 92
    if MODEL_BUNDLE:
        model = MODEL_BUNDLE["model"]; prediction = int(model.predict([features(row)])[0]); probabilities = model.predict_proba([features(row)])[0]; is_threat = bool(prediction); confidence = round(float(max(probabilities)) * 100)
    classification = row.get("attack_classification", "Threat" if is_threat else "Normal") if is_threat else "Normal"
    return {**row, "target_port": int(row["target_port"]), "packet_size": int(row["packet_size"]), "payload_entropy": float(row["payload_entropy"]), "ttl": int(row.get("ttl", 64)), "label": int(is_threat), "classification": "Threat" if is_threat else "Normal", "threat_type": classification, "confidence": confidence, "severity": "critical" if classification == "Volumetric DoS" else ("warning" if classification == "Reconnaissance" else "normal")}

@app.get("/health")
def health(): return {"status": "ok", "mode": "playback", "model_loaded": MODEL_BUNDLE is not None, "records": len(rows()) if DATA_PATH.exists() else 0, "cadence_seconds": 1}

@app.post("/analyze")
def analyze_packet(packet: Packet): return analyze({**packet.model_dump(), "timestamp": datetime.now(timezone.utc).isoformat(), "destination_ip": "10.0.0.10", "tcp_flags": "ACK", "ttl": 64, "mac_address": "02:42:ac:11:00:10", "attack_classification": "Normal"})

async def event_stream(loop: bool) -> AsyncIterator[str]:
    dataset = rows()
    while True:
        for row in dataset:
            yield f"data: {json.dumps(analyze(row))}\n\n"
            await asyncio.sleep(1)
        if not loop: break
        yield f"event: playback_reset\ndata: {json.dumps({'mode':'playback','message':'Dataset replay restarted'})}\n\n"

@app.get("/stream")
async def stream(loop: bool = Query(True, description="Replay from the first packet after the last record.")):
    return StreamingResponse(event_stream(loop), media_type="text/event-stream", headers={"Cache-Control":"no-cache", "Connection":"keep-alive", "X-Accel-Buffering":"no"})
