# Attachment review: extracted requirements

The attachment supersedes the original live-listener wording for the demo architecture. The backend must be a controlled **playback engine**, not a live network listener. It should sequentially read a generated PCAP or detailed PCAP-like CSV, run each record through the trained model, and stream results via SSE or WebSocket at a predictable one-second cadence.

| Requirement | Planned implementation |
|---|---|
| Generate realistic PCAP or detailed CSV metadata | Add `backend/generate_pcap.py` using Scapy when available, with a CSV fallback containing normal traffic, volumetric DoS, and sequential reconnaissance rows. |
| Train a scikit-learn model from packet features | Update training to use Size, Protocol, Port, entropy, and attack labels, while keeping the persisted pickle artifact. |
| Playback-only backend | Replace random live simulation with sequential dataset replay and `/stream?loop=true` controls. |
| One second of packet data per real-world second | Stream one analyzed packet every second, with a deterministic index and playback metadata. |
| KPIs only for total packets and average confidence | Remove Threats Blocked from the dashboard and retain the required two metrics. |
| Packets/sec chart with normal and threat lines | Update chart labels and dataset semantics to packets per second. |
| Mask repetitive IP hierarchy | De-emphasize source and destination IPs, right-aligning them in low-contrast text. |
| Emphasize timestamp, target port, classification | Keep these left-aligned and bright in the threat log. |
| Red DoS and yellow reconnaissance badges | Use exact attack-aware badge colors. |
| Packet Inspector | Add clickable threat rows and a slide-out inspector showing packet size, TCP flags, TTL, and MAC address. |
| Static inspector fallback allowed | Populate generated playback rows with deterministic raw metadata, and retain safe UI fallback values. |

The existing polished Signal Room visual system remains the design foundation. The major behavior change is that “Connect backend” will connect to a deterministic playback stream rather than a random live listener.
