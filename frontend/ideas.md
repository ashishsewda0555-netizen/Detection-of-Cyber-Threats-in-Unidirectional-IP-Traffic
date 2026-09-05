# SIH26145 SOC Dashboard — Design Direction

## Three Initial Approaches

### Theme Name: Signal Room
Very dark, editorial command-center aesthetic with lime telemetry highlights and disciplined data density. The interface feels like an always-on operations floor rather than a generic admin panel.

**Probability:** 0.07

### Theme Name: Iceberg Protocol
Cool, clinical interface using blue-white surfaces, forensic labels, and diagram-like structure. The emotional intent is calm authority and incident clarity.

**Probability:** 0.03

### Theme Name: Carbon Relay
Industrial black-carbon surfaces, amber warnings, and mechanical control-room details. The experience feels tactile, operational, and built for fast scanning.

**Probability:** 0.09

## Chosen Approach: Signal Room

### Design Movement
Contemporary editorial data visualization fused with mission-control instrument panels: high-contrast typography, asymmetrical composition, and restrained technical ornament.

### Core Principles
1. **Operational hierarchy:** Every region answers a monitoring question quickly: what is flowing, what is anomalous, and what needs action.
2. **Sparse signal color:** A signature acid-lime accent marks live telemetry, while coral-red and amber are reserved for threat state.
3. **Asymmetric rhythm:** A persistent navigation rail, wide monitoring canvas, and narrow incident column create a command-center silhouette rather than a centered card grid.
4. **Quiet depth:** Graphite layers, hairline borders, subtle bloom, and soft shadows create depth without noisy neon effects.

### Color Philosophy
The base is near-black graphite to reduce glare during long monitoring sessions. Acid lime (#C7F36B) represents live signal and system health, while warm amber (#F4B860) and coral (#FF6B61) convey escalating risk. Cool slate text keeps the system legible and forensic rather than theatrical.

### Layout Paradigm
A fixed left rail anchors context. The main workspace uses a split monitoring canvas: KPI ribbon and live traffic chart on the left, a compact incident digest on the right, then a full-width threat log beneath. On smaller screens, the rail compresses to an icon strip and the incident digest moves above the log.

### Signature Elements
- Lime “live line” marker and pulsing status dot.
- Monospaced telemetry labels paired with editorial serif display numbers.
- Thin coordinate ticks and tiny protocol metadata around chart and cards.

### Interaction Philosophy
Interactions should feel like confirming an instrument, not decorating a dashboard. Hover states reveal metadata, table rows lift subtly, and control toggles snap into an active state. The demo mode remains visibly connected even when the real FastAPI stream is unavailable, making local setup frictionless.

### Animation
Use 160–220ms transitions with a strong ease-out. KPI values ease upward on change, the live status dot pulses slowly, and new threat rows enter with a short opacity/translate reveal. Never animate layout dimensions; respect reduced-motion preferences.

### Typography System
Use **Space Grotesk** for interface hierarchy and **IBM Plex Mono** for all telemetry, timestamps, IPs, protocols, and metric captions. Large numeric KPIs use Space Grotesk in a heavy weight with tight tracking; body labels remain compact and sentence case.

### Brand Essence
A live threat-sensing command surface for security teams who need explainable signal, not dashboard theater.

**Personality:** vigilant, precise, composed.

### Brand Voice
Headlines are short and declarative. CTAs sound like operator actions. Microcopy reports state without drama.

- “See the signal before it becomes an incident.”
- “Replay stream”

### Wordmark & Logo
The mark is a small angular sentinel: two offset brackets enclosing a single lime pulse, suggesting a protected one-way channel. The wordmark is set in Space Grotesk with the “AI” pair slightly tracked out, while the icon remains independently recognizable as a favicon.

### Signature Brand Color
**Signal Lime — #C7F36B.** It is the visual proof that telemetry is alive and being evaluated.
