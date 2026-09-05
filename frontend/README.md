# Signal Room — SIH26145 Cyber Threat SOC

A complete, crash-resistant demo prototype for **SIH26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**. The project uses a reproducible PCAP-like playback dataset, a lightweight scikit-learn classifier, a FastAPI sequential replay engine with Server-Sent Events, and a responsive React SOC dashboard. The backend is deliberately **playback-only**: it never opens a live network interface.

> This is a research/demo prototype. The generated traffic is synthetic and the detector should be calibrated and validated against representative production telemetry before operational use.

## Architecture

| Layer | Implementation | Responsibility |
|---|---|---|
| Playback dataset | `backend/generate_pcap.py` | Emits sequential PCAP-like CSV metadata with normal traffic, a volumetric DoS window, and a rolling reconnaissance port scan; optionally writes a real `.pcap` when Scapy is installed. |
| ML pipeline | `backend/train_model.py` | Encodes packet features and trains a Random Forest classifier; persists `backend/models/threat_detector.pkl`. |
| Playback API | `backend/main.py` | Loads the dataset and model, analyzes records sequentially, and exposes `/health`, `/analyze`, and `/stream?loop=true` at one packet per real-world second. |
| SOC dashboard | `client/src/pages/Home.tsx` | Shows live KPIs, Chart.js traffic profile, incident digest, confidence bars, and severity-tagged threat log. |

## Feature schema

The model uses five numeric features: normalized target port, normalized packet size, normalized payload entropy, and one-hot indicators for TCP and UDP. Source IP is retained for analyst context but is not directly learned as a categorical feature. The stream includes the original packet fields plus `classification`, `confidence`, `severity`, and `threat_type`.

| Field | Example | Meaning |
|---|---:|---|
| `source_ip` | `185.14.72.19` | Origin of the inbound flow. |
| `target_port` | `443` | Destination service port. |
| `packet_size` | `1944` | Packet size in bytes. |
| `protocol` | `TCP` | Transport/network protocol. |
| `payload_entropy` | `8.42` | Synthetic payload entropy score from 0–8. |
| `classification` | `Threat` | Binary model outcome. |
| `confidence` | `98` | Presentation score from 0–100. |

## Prerequisites

Use Python 3.10+ and Node.js 18+ with pnpm. The frontend is already scaffolded as a React + Vite project. The backend is intentionally a separate local process so it can later be placed behind a sensor or unidirectional gateway.

## Run the ML pipeline

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
python backend/generate_pcap.py --count 300 --output backend/data/playback.csv
python backend/train_model.py --data backend/data/playback.csv
```

The generator creates `backend/data/playback.csv`, where packet `sequence` values are monotonic and timestamps are one second apart. Use `--pcap backend/data/playback.pcap` to also emit a Scapy PCAP when desired. The trainer prints a classification report and writes `backend/models/threat_detector.pkl`. Re-run both commands whenever you change the feature or threat-generation logic.

## Start the FastAPI listener

With the virtual environment active:

```bash
uvicorn backend.main:app --reload --port 8000
```

The API is available at `http://localhost:8000`. Useful endpoints:

```bash
curl http://localhost:8000/health
curl -N http://localhost:8000/stream
curl -X POST http://localhost:8000/analyze \\
  -H 'content-type: application/json' \\
  -d '{"source_ip":"10.24.4.8","target_port":443,"packet_size":620,"protocol":"TCP","payload_entropy":3.8}'
```

The `/stream` endpoint uses SSE with `data: <JSON>\\n\\n` messages. It replays the dataset sequentially, waits exactly one second between records, and loops by default for a judge-friendly controlled demo. Use `/stream?loop=false` for a single pass. The backend is CORS-enabled for local frontend development.

## Start the SOC dashboard

In a second terminal:

```bash
pnpm install
pnpm dev
```

Open the Vite URL printed in the terminal. The dashboard starts in **local simulation mode**, so it is immediately demonstrable without the Python server. Click **Connect backend** to subscribe to `http://localhost:8000/stream`. If the backend is unavailable, the dashboard falls back to its local stream and remains usable.

To point the dashboard at another listener, set the Vite variable before starting it:

```bash
VITE_API_URL=http://localhost:8000 pnpm dev
```

## Dashboard behavior

The dashboard provides the required headline KPIs—**Total Packets Analyzed** and **Average AI Confidence**—plus a model status card. It includes a Chart.js **Packets/sec** line graph for normal versus anomalous traffic, a threat pulse digest, and a stream inspection table. Timestamp, target port, and attack classification are bright and left-weighted; source and destination IP fields are intentionally de-emphasized. Volumetric DoS rows use bright red badges, while Reconnaissance rows use bright yellow badges. Clicking a threat row opens the Packet Inspector drawer with packet size, TCP flags, TTL, MAC address, target port, entropy, and model decision.

The anomaly score is converted to a bounded percentage for operator readability. Confidence is a prioritization aid rather than a calibrated probability. In a production deployment, replace the synthetic score mapping with calibrated probabilities and add model drift monitoring, an allowlist/denylist policy layer, immutable audit storage, authentication, and a sensor adapter for the actual one-way link.

## Project structure

```text
.
├── README.md
├── requirements.txt
├── ideas.md
├── backend/
│   ├── data/playback.csv                           # generated sequential playback dataset
│   ├── models/threat_detector.pkl                  # trained artifact
│   ├── generate_pcap.py
│   ├── train_model.py
│   └── main.py
└── client/
    ├── index.html
    └── src/
        ├── App.tsx
        ├── index.css
        └── pages/Home.tsx
```

## Verification checklist

Run `pnpm check` for TypeScript validation and `pnpm build` for the production frontend build. For the Python side, run `generate_pcap.py`, train the model, start Uvicorn, confirm `/health` reports `mode: playback` and `model_loaded: true`, then inspect sequential events from `/stream`. The prototype uses SSE rather than WebSocket because the flow is naturally server-to-client and the dashboard does not need to send control frames to the playback engine.

## License

MIT for the prototype code. Generated synthetic traffic is not real network data and contains no customer or personal telemetry.

## Workspace navigation

Each left-rail item changes the rendered workspace while preserving the same visual system and live state. **Overview** is the main SOC summary, **Traffic Monitor** focuses on ingress-to-analysis flow and recent packet checkpoints, **Threat Intel** provides attack-family counts and confidence rows, and **Model Health** presents Random Forest posture plus feature contribution indicators. Returning to Overview does not reset the playback state.
