"""
api_server.py — In-Memory FastAPI Backend for DDoS Sentinel

Replaces the legacy disk-bound pipeline (live_stream.csv → Streamlit polling)
with a zero-disk-I/O, API-driven architecture:

  live_capture.py  ──POST JSON──►  api_server.py  ──SSE push──►  React Frontend
     (Scapy)                       (FastAPI)                     (EventSource)
                                      │
                                      ▼
                                  scorer.py
                              (in-memory inference)

Endpoints:
  POST /api/score   — Receive a 5-second feature window, score it, push to SSE clients
  GET  /api/stream  — SSE stream of all scored verdicts (for React frontend)
  GET  /api/health  — Health check (confirms model is loaded)

Start with:
  uvicorn api_server:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

# ──────────────────────────────────────────────
# Configuration from .env
# ──────────────────────────────────────────────
load_dotenv()

API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
VICTIM_IP = os.getenv("VICTIM_IP", "192.168.100.2")

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ddos_sentinel_api")

# ──────────────────────────────────────────────
# SSE Client Manager
# ──────────────────────────────────────────────
class SSEClientManager:
    """Manages connected SSE clients using asyncio.Queue fan-out.
    
    Each connected client gets its own queue. When a new verdict is scored,
    it is broadcast to every queue — zero disk I/O, pure in-memory streaming.
    """

    def __init__(self):
        self._clients: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()
        # Rolling buffer of the last N verdicts for late-joining clients
        self._history: list[dict] = []
        self._max_history = 50

    async def connect(self) -> asyncio.Queue:
        """Register a new SSE client and return its dedicated queue."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._clients.append(queue)
        logger.info(f"SSE client connected. Total clients: {len(self._clients)}")
        return queue

    async def disconnect(self, queue: asyncio.Queue):
        """Remove a disconnected SSE client."""
        async with self._lock:
            if queue in self._clients:
                self._clients.remove(queue)
        logger.info(f"SSE client disconnected. Total clients: {len(self._clients)}")

    async def broadcast(self, verdict: dict):
        """Push a scored verdict to ALL connected SSE clients."""
        async with self._lock:
            # Store in rolling history
            self._history.append(verdict)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

            # Fan-out to all client queues
            disconnected = []
            for queue in self._clients:
                try:
                    queue.put_nowait(verdict)
                except asyncio.QueueFull:
                    # Client is too slow — drop oldest item and retry
                    try:
                        queue.get_nowait()
                        queue.put_nowait(verdict)
                    except Exception:
                        disconnected.append(queue)

            # Clean up any broken queues
            for q in disconnected:
                if q in self._clients:
                    self._clients.remove(q)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    @property
    def history(self) -> list[dict]:
        return list(self._history)


# ──────────────────────────────────────────────
# Application Lifecycle
# ──────────────────────────────────────────────
sse_manager = SSEClientManager()

# Track cumulative stats in memory
stats = {
    "total_windows": 0,
    "critical_alerts": 0,
    "high_alerts": 0,
    "medium_alerts": 0,
    "port_scans": 0,
    "benign_windows": 0,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the ML model once at startup, before any requests are served."""
    logger.info("Loading scorer module (model + SHAP explainer)...")
    # Import scorer at startup — this triggers model loading and SHAP init
    from backend.scorer import score_window  # noqa: F401
    logger.info("Scorer loaded successfully. API is ready.")
    yield
    logger.info("Shutting down API server.")


# ──────────────────────────────────────────────
# FastAPI App
# ──────────────────────────────────────────────
app = FastAPI(
    title="DDoS Sentinel API",
    description="In-memory dual-engine DDoS detection with SSE streaming",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — allow the React frontend (likely on a different port) to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
# POST /api/score — Receive & Score a Feature Window
# ──────────────────────────────────────────────
@app.post("/api/score")
async def score_feature_window(request: Request) -> dict[str, Any]:
    """
    Receives a 5-second feature window from live_capture.py as JSON,
    scores it in-memory via scorer.score_window(), and broadcasts the
    verdict to all connected SSE clients.

    Expected JSON body (example):
    {
        "flow_rate": 2.0,
        "packet_rate": 2.0,
        "fwd_bwd_ratio": 1.0,
        "unique_src_count": 1,
        "syn_flag_sum": 0,
        "ack_flag_sum": 2,
        "syn_ack_ratio": 0.0,
        "avg_packet_size": 150.0,
        "packet_size_std": 20.0,
        "Dst_IP": "192.168.100.2",
        "Window_Start": "2026-09-05T12:00:00+00:00",
        "unique_dst_ports": 3
    """
    from backend.scorer import score_window

    features = await request.json()

    # Score the window in-memory (no disk I/O)
    verdict = score_window(features)

    # Update cumulative stats
    stats["total_windows"] += 1
    if verdict.get("is_alert"):
        severity = verdict.get("severity", "")
        threat = verdict.get("threat_class", "")
        if threat == "port_scan":
            stats["port_scans"] += 1
        elif severity == "critical":
            stats["critical_alerts"] += 1
        elif severity == "high":
            stats["high_alerts"] += 1
        elif severity == "medium":
            stats["medium_alerts"] += 1
    else:
        stats["benign_windows"] += 1

    # Broadcast to all connected SSE clients (in-memory fan-out)
    await sse_manager.broadcast(verdict)

    logger.info(
        f"Window scored: is_alert={verdict.get('is_alert')} | "
        f"threat={verdict.get('threat_class', 'benign')} | "
        f"total={stats['total_windows']}"
    )

    return verdict


# ──────────────────────────────────────────────
# GET /api/stream — Server-Sent Events (SSE)
# ──────────────────────────────────────────────
@app.get("/api/stream")
async def sse_stream(request: Request):
    """
    SSE endpoint. The React frontend opens a persistent EventSource connection
    here and receives pushed JSON verdicts in real-time.

    Usage (JavaScript):
        const evtSource = new EventSource("http://localhost:8000/api/stream");
        evtSource.onmessage = (event) => {
            const verdict = JSON.parse(event.data);
            // render verdict in UI
        };
    """
    queue = await sse_manager.connect()

    async def event_generator():
        try:
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break

                try:
                    # Wait for the next verdict (with timeout to check disconnect)
                    verdict = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(verdict)}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive comment to prevent connection timeout
                    yield ": keepalive\n\n"
        finally:
            await sse_manager.disconnect(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering if behind proxy
        },
    )


# ──────────────────────────────────────────────
# GET /api/health — Health Check
# ──────────────────────────────────────────────
@app.get("/api/health")
async def health_check():
    """Returns server status, connected client count, and cumulative stats."""
    return {
        "status": "ok",
        "model_loaded": True,
        "sse_clients": sse_manager.client_count,
        "stats": stats,
    }


# ──────────────────────────────────────────────
# GET /api/history — Recent Verdict History
# ──────────────────────────────────────────────
@app.get("/api/history")
async def get_history():
    """Returns the last 50 scored verdicts (for late-joining clients)."""
    return {"verdicts": sse_manager.history}


# ──────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    logger.info(f"Starting DDoS Sentinel API on {API_HOST}:{API_PORT}")
    uvicorn.run(
        "api_server:app",
        host=API_HOST,
        port=API_PORT,
        reload=False,
        log_level="info",
    )
