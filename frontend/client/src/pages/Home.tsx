// Signal Room style: asymmetric command-center layout, graphite layers, lime telemetry, compact mono labels.
import { useEffect, useMemo, useRef, useState } from "react";
import { Chart, LineController, LineElement, PointElement, LinearScale, CategoryScale, Filler, Tooltip } from "chart.js";
import { Activity, AlertTriangle, ArrowUpRight, Bell, CircleDot, Cpu, Database, Gauge, Radio, ShieldAlert, Wifi, Zap } from "lucide-react";
import { useSSEStream, type TrafficPacket, type HealthStatus } from "@/hooks/useSSEStream";

Chart.register(LineController, LineElement, PointElement, LinearScale, CategoryScale, Filler, Tooltip);

// ── Demo-mode helpers (kept for fallback when the backend is offline) ──

const threatProfiles = [
  { type: "Volumetric DoS", severity: "critical" as const, ports: [80, 443, 8080] },
  { type: "Port scan", severity: "warning" as const, ports: [22, 23, 3389] },
  { type: "Malicious payload", severity: "critical" as const, ports: [445, 1433, 8443] },
];

function makePacket(): TrafficPacket {
  const threat = Math.random() < 0.18 ? threatProfiles[Math.floor(Math.random() * threatProfiles.length)] : null;
  const now = new Date();
  const confidence = threat ? 82 + Math.round(Math.random() * 16) : 91 + Math.round(Math.random() * 8);
  return {
    timestamp: now.toISOString(), source_ip: threat ? `185.14.${Math.floor(Math.random() * 240)}.${Math.floor(Math.random() * 240)}` : `10.24.${Math.floor(Math.random() * 18)}.${Math.floor(Math.random() * 240)}`,
    target_port: threat ? threat.ports[Math.floor(Math.random() * threat.ports.length)] : [443, 53, 123, 80][Math.floor(Math.random() * 4)],
    packet_size: threat?.type === "DDoS spike" ? 1200 + Math.floor(Math.random() * 1100) : 180 + Math.floor(Math.random() * 930),
    protocol: ["TCP", "UDP", "ICMP"][Math.floor(Math.random() * 3)], payload_entropy: threat?.type === "Malicious payload" ? 7.7 + Math.random() : 2.1 + Math.random() * 4.4,
    threat_type: threat?.type ?? "Clean flow", classification: threat ? "Threat" : "Normal", confidence, severity: threat?.severity ?? "normal",
  };
}

const seedThreats: TrafficPacket[] = [
  { timestamp: new Date(Date.now() - 38000).toISOString(), source_ip: "185.14.72.19", target_port: 445, packet_size: 1944, protocol: "TCP", payload_entropy: 8.42, threat_type: "Malicious payload", classification: "Threat", confidence: 98, severity: "critical" },
  { timestamp: new Date(Date.now() - 84000).toISOString(), source_ip: "185.14.201.6", target_port: 3389, packet_size: 1487, protocol: "TCP", payload_entropy: 4.85, threat_type: "Port scan", classification: "Threat", confidence: 91, severity: "warning" },
  { timestamp: new Date(Date.now() - 142000).toISOString(), source_ip: "91.204.18.77", target_port: 443, packet_size: 2048, protocol: "UDP", payload_entropy: 6.15, threat_type: "DDoS spike", classification: "Threat", confidence: 96, severity: "critical" },
];

function formatTime(iso: string) { return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }); }
function formatNumber(value: number) { return new Intl.NumberFormat("en-US").format(value); }

// ── SHAP Evidence display for the Packet Inspector ──

function EvidenceGrid({ evidence }: { evidence?: Record<string, number> }) {
  if (!evidence || Object.keys(evidence).length === 0) return null;
  return (
    <div className="raw-grid" style={{ marginTop: 12 }}>
      <div style={{ gridColumn: "1 / -1" }}>
        <span className="section-kicker">SHAP FEATURE CONTRIBUTIONS</span>
      </div>
      {Object.entries(evidence).map(([feature, value]) => (
        <div key={feature}>
          <span>{feature.replace(/_/g, " ").toUpperCase()}</span>
          <strong style={{ color: value > 0 ? "#ff6b61" : "#c7f36b" }}>
            {value > 0 ? "+" : ""}{typeof value === "number" ? value.toFixed(4) : value}
          </strong>
        </div>
      ))}
    </div>
  );
}

// ── Auxiliary views (Traffic monitor, Threat intel, Model health) ──

function AuxiliaryView({ activeSection, setActiveSection, connected, packets, threats, health }: { activeSection: string; setActiveSection: (section: string) => void; connected: boolean; packets: TrafficPacket[]; threats: TrafficPacket[]; health: HealthStatus | null }) {
  const viewCopy: Record<string, { kicker: string; title: string; intro: string }> = {
    "Traffic monitor": { kicker: "01 / PACKET FLOW", title: "Traffic monitor", intro: "Inspect the controlled playback stream as it crosses the one-way analysis boundary." },
    "Threat intel": { kicker: "02 / INCIDENT WORKBENCH", title: "Threat intelligence", intro: "Triage attack classifications, confidence signals, and packet-level evidence." },
    "Model health": { kicker: "03 / INFERENCE TELEMETRY", title: "Model health", intro: "Review the current classifier posture and the feature signals driving decisions." },
  };
  const copy = viewCopy[activeSection];
  const protocolCounts = packets.reduce<Record<string, number>>((acc, packet) => ({ ...acc, [packet.protocol]: (acc[packet.protocol] || 0) + 1 }), {});

  // Compute real stats from health endpoint or fallback to local data
  const stats = health?.stats;
  const totalWindows = stats?.total_windows ?? packets.length;
  const criticalCount = stats?.critical_alerts ?? threats.filter(t => t.severity === "critical").length;
  const highCount = stats?.high_alerts ?? 0;
  const mediumCount = stats?.medium_alerts ?? 0;
  const portScanCount = stats?.port_scans ?? threats.filter(t => t.threat_type === "Port Scan" || t.threat_type === "Port scan").length;
  const benignCount = stats?.benign_windows ?? packets.filter(p => p.classification === "Normal").length;
  const modelConfidence = totalWindows > 0 ? Math.round((benignCount / Math.max(totalWindows, 1)) * 100) : 97;

  // Compute feature contribution from the latest evidence data
  const latestThreatWithEvidence = threats.find(t => t.evidence && Object.keys(t.evidence).length > 0);
  const featureData = latestThreatWithEvidence?.evidence
    ? Object.entries(latestThreatWithEvidence.evidence).map(([label, val]) => {
        const absVal = Math.abs(val);
        const width = Math.min(Math.round(absVal * 100), 100);
        const state = absVal > 0.5 ? "High" : absVal > 0.2 ? "Elevated" : absVal > 0.1 ? "Moderate" : "Stable";
        return [label.replace(/_/g, " "), state, width] as [string, string, number];
      })
    : [["Exfiltration ratio", "High", 86], ["Orig bytes", "Elevated", 74], ["Resp bytes", "Moderate", 61], ["Resp port", "Stable", 42]] as [string, string, number][];

  return <div className="aux-shell"><aside className="aux-rail"><div className="brand"><img src="/manus-storage/signal-room-sentinel_222b9f60.png" alt="Signal Room sentinel" /><div><strong>signal<span>/</span>room</strong><small>THREAT SENSING GRID</small></div></div><div className="rail-label">WORKSPACE</div><nav>{["Overview", "Threat intel", "Model health"].map(name => <button key={name} className={activeSection === name ? "nav-active" : ""} onClick={() => setActiveSection(name)}><Activity size={16} /><span>{name}</span>{name === "Threat intel" && <b>{String(threats.length).padStart(2, "0")}</b>}</button>)}</nav><div className="aux-rail-foot"><span className="status-dot" /> {connected ? "ML PIPELINE CONNECTED" : "DEMO FALLBACK"}</div></aside><main className="aux-main"><div className="eyebrow"><span className="live-pip" /> LIVE OPERATIONS / {activeSection.toUpperCase()}</div><div className="aux-title-row"><div><h1>{copy.title}</h1><p>{copy.intro}</p></div><div className={`connection-pill ${connected ? "is-connected" : "is-offline"}`}><Wifi size={14} /> {connected ? "Pipeline active" : "Demo mode"}</div></div>{activeSection === "Threat intel" && <section className="panel intelligence-board"><div className="panel-heading"><div><span className="section-kicker">{copy.kicker}</span><h2>Attack signatures {connected ? "detected" : "in replay"}</h2></div><span className="count-badge">{String(threats.length).padStart(2, "0")}</span></div><div className="intel-cards"><div className="intel-card dos"><span className="attack-badge dos">VOLUMETRIC DOS</span><strong>{threats.filter(t => t.threat_type === "Volumetric DoS" || t.threat_type === "Volumetric DDoS" || t.threat_type === "DDoS spike" || t.threat_type === "SYN Flood DDoS").length}</strong><small>high-volume service exhaustion pattern</small></div><div className="intel-card recon"><span className="attack-badge recon">RECONNAISSANCE</span><strong>{threats.filter(t => t.threat_type === "Port scan" || t.threat_type === "Port Scan").length + portScanCount}</strong><small>sequential target-port discovery pattern</small></div><div className="intel-card"><span className="attack-badge neutral">{connected ? "DATA EXFILTRATION" : "MALICIOUS PAYLOAD"}</span><strong>{threats.filter(t => t.threat_type === "Data Exfiltration" || t.threat_type === "Malicious payload" || t.threat_type === "Unknown DDoS Variant").length}</strong><small>{connected ? "high exfiltration ratio anomaly" : "high-entropy payload anomaly"}</small></div></div><div className="intel-table">{threats.map((threat, index) => <button key={`${threat.timestamp}-${index}`} onClick={() => setActiveSection("Threat intel")}><span className={`type-marker ${threat.severity}`} /><strong>{threat.threat_type}</strong><span className="mono">{threat.source_ip}</span><b>{threat.confidence}%</b></button>)}</div></section>}{activeSection === "Model health" && <section className="aux-grid model-health-grid"><div className="panel score-card"><span className="section-kicker">{copy.kicker}</span><h2>{connected ? "Dual-Engine posture" : "Random Forest posture"}</h2><div className="health-score"><strong>{modelConfidence}<sup>%</sup></strong><span>operational confidence</span></div><div className="health-meter"><span style={{ width: `${modelConfidence}%` }} /></div>{connected && stats ? <p>Dual-engine pipeline active (Zeek). {totalWindows} flows scored: {criticalCount} critical, {highCount} high, {mediumCount} medium alerts. {benignCount} benign. {health?.sse_clients ?? 0} SSE client(s) connected.</p> : <p>Feature inputs are arriving within expected ranges. The playback engine is supplying a stable, labeled stream for demo inference.</p>}</div><div className="panel feature-card"><span className="section-kicker">FEATURE CONTRIBUTION</span><h2>Decision signals</h2>{featureData.map(([label, state, width]) => <div className="feature-row" key={label as string}><div><strong>{label}</strong><small>{state}</small></div><div className="progress-track"><span style={{ width: `${width}%` }} /></div></div>)}</div></section>}<footer className="footer"><span>© 2026 SIGNAL ROOM / SIH26145 PROTOTYPE</span><span><span className="status-dot" /> {connected ? `ML PIPELINE / ${health?.sse_clients ?? 0} CLIENTS` : "PLAYBACK ENGINE / 1.0s CADENCE"}</span></footer></main></div>;
}

// ── Main Home component ──

export default function Home() {
  const [streamMode, setStreamMode] = useState<"demo" | "sse" | "stress">("sse");
  const [paused, setPaused] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState<TrafficPacket | null>(null);
  const [activeSection, setActiveSection] = useState("Overview");
  const [chartPoints, setChartPoints] = useState(() => Array.from({ length: 18 }, (_, i) => ({ label: `${String(i + 43).padStart(2, "0")}:1${i % 10}`, normal: 36 + Math.round(Math.random() * 20), anomalous: i > 14 ? 7 + Math.round(Math.random() * 5) : 2 + Math.round(Math.random() * 4) })));
  const chartRef = useRef<HTMLCanvasElement>(null);
  const chartInstance = useRef<Chart | null>(null);

  // ── Demo-mode local state (used when backend is offline) ──
  const [demoPackets, setDemoPackets] = useState<TrafficPacket[]>([]);
  const [demoThreats, setDemoThreats] = useState<TrafficPacket[]>(seedThreats);

  // ── Real ML pipeline SSE hook ──
  const sse = useSSEStream({ enabled: streamMode === "sse" });

  // When the SSE hook signals fallback (backend unreachable), auto-switch to demo
  useEffect(() => {
    if (sse.fallback && streamMode === "sse") {
      setStreamMode("demo");
    }
  }, [sse.fallback, streamMode]);

  // Merge: use real data when SSE is active, otherwise demo data
  const packets = streamMode === "sse" ? sse.packets : demoPackets;
  const threats = streamMode === "sse" ? sse.threats : demoThreats;
  const connected = streamMode === "sse" ? sse.connected : true;
  const health = streamMode === "sse" ? sse.health : null;

  const total = (health?.stats?.total_windows ?? 18420) + packets.length;
  const avgConfidence = packets.length ? Math.round(packets.reduce((sum, packet) => sum + packet.confidence, 0) / packets.length) : 97;

  // ── Demo mode timer (only fires when in demo mode) ──
  useEffect(() => {
    if (streamMode !== "demo" || paused) return;
    const timer = window.setInterval(() => {
      const packet = makePacket();
      setDemoPackets(current => [...current.slice(-80), packet]);
      if (packet.classification === "Threat") setDemoThreats(current => [packet, ...current].slice(0, 12));
      setChartPoints(current => [...current.slice(-17), { label: formatTime(packet.timestamp).slice(3, 8), normal: packet.classification === "Normal" ? 42 + Math.round(Math.random() * 20) : 31 + Math.round(Math.random() * 12), anomalous: packet.classification === "Threat" ? 10 + Math.round(Math.random() * 8) : 2 + Math.round(Math.random() * 4) }]);
    }, 1450);
    return () => window.clearInterval(timer);
  }, [streamMode, paused]);

  // ── Stress test mode timer ──
  useEffect(() => {
    if (streamMode !== "stress" || paused) return;
    const testData = [
      {
        "flow_id": "10.0.1.50-192.168.1.1-54321-443",
        "timestamp": "2026-09-05 12:02:40.000000+00:00",
        "src_ip": "10.0.1.50",
        "dst_ip": "192.168.1.1",
        "proto": "tcp",
        "anomaly_score": 0.025,
        "classifier_probability": 1.0,
        "is_alert": false
      },
      {
        "flow_id": "185.14.72.19-192.168.1.1-12345-80",
        "timestamp": "2026-09-05 12:02:48.264707+00:00",
        "src_ip": "185.14.72.19",
        "dst_ip": "192.168.1.1",
        "proto": "tcp",
        "anomaly_score": 0.868,
        "classifier_probability": 0.605,
        "is_alert": true,
        "threat_class": "ddos_syn_flood",
        "confidence": 0.99,
        "severity": "critical",
        "evidence": {
          "orig_bytes": 60,
          "resp_bytes": 0,
          "exfiltration_ratio": 60.0
        }
      },
      {
        "flow_id": "10.0.1.100-192.168.1.5-8080-443",
        "timestamp": "2026-09-05 12:03:36.472707+00:00",
        "src_ip": "10.0.1.100",
        "dst_ip": "192.168.1.5",
        "proto": "tcp",
        "anomaly_score": 0.036,
        "classifier_probability": 1.0,
        "is_alert": false
      }
    ];

    let index = 0;
    // We can clear previous demo packets/threats on start to make it pristine
    setDemoPackets([]);
    setDemoThreats([]);
    
    const timer = window.setInterval(() => {
      if (index >= testData.length) {
        window.clearInterval(timer);
        return;
      }
      
      const raw = testData[index];
      const packet: TrafficPacket = {
        timestamp: raw.timestamp,
        source_ip: raw.src_ip,
        dst_ip: raw.dst_ip,
        target_port: 0,
        packet_size: 0,
        protocol: "TCP",
        payload_entropy: 0,
        anomaly_score: raw.anomaly_score,
        classifier_probability: raw.classifier_probability,
        flow_id: raw.flow_id,
        threat_type: raw.threat_class === "ddos_spoofed_syn_flood" ? "SYN Flood DDoS" : raw.threat_class || "Clean flow",
        classification: raw.is_alert ? "Threat" : "Normal",
        confidence: raw.is_alert ? (raw.confidence ? raw.confidence * 100 : 99) : 99,
        severity: (raw.severity as any) || "normal",
        evidence: raw.evidence
      };
      
      setDemoPackets(current => [...current.slice(-80), packet]);
      if (packet.classification === "Threat") setDemoThreats(current => [packet, ...current].slice(0, 12));
      setChartPoints(current => [...current.slice(-17), { label: formatTime(packet.timestamp).slice(3, 8), normal: packet.classification === "Normal" ? 42 + Math.round(Math.random() * 20) : 31 + Math.round(Math.random() * 12), anomalous: packet.classification === "Threat" ? 10 + Math.round(Math.random() * 8) : 2 + Math.round(Math.random() * 4) }]);
      
      index++;
    }, 5000);
    
    return () => window.clearInterval(timer);
  }, [streamMode, paused]);

  // ── Update chart from SSE packets ──
  useEffect(() => {
    if (streamMode !== "sse" || packets.length === 0) return;
    const latest = packets[packets.length - 1];
    setChartPoints(current => [...current.slice(-17), {
      label: formatTime(latest.timestamp).slice(3, 8),
      normal: latest.classification === "Normal" ? 42 + Math.round(Math.random() * 20) : 31 + Math.round(Math.random() * 12),
      anomalous: latest.classification === "Threat"
        ? (latest.evidence?.exfiltration_ratio ?? latest.evidence?.orig_bytes ?? Math.round((latest.anomaly_score ?? 0.5) * 20) + 5)
        : 2 + Math.round(Math.random() * 4),
    }]);
  }, [streamMode, packets.length]);

  // ── Chart.js rendering ──
  useEffect(() => {
    if (!chartRef.current) return;
    chartInstance.current?.destroy();
    chartInstance.current = new Chart(chartRef.current, {
      type: "line", data: { labels: chartPoints.map(point => point.label), datasets: [
        { label: "Normal traffic", data: chartPoints.map(point => point.normal), borderColor: "#c7f36b", backgroundColor: "rgba(199,243,107,.09)", fill: true, tension: .42, pointRadius: 0, borderWidth: 2 },
        { label: "Anomalous traffic", data: chartPoints.map(point => point.anomalous), borderColor: "#ff6b61", backgroundColor: "rgba(255,107,97,.07)", fill: true, tension: .42, pointRadius: 0, borderWidth: 2 },
      ] }, options: { responsive: true, maintainAspectRatio: false, animation: { duration: 250 }, plugins: { legend: { display: false }, tooltip: { backgroundColor: "#111715", borderColor: "#303b35", borderWidth: 1, titleColor: "#d7e0d9", bodyColor: "#9baa9d", displayColors: true } }, scales: { x: { grid: { color: "rgba(145,163,151,.09)" }, ticks: { color: "#6c7a70", font: { family: "IBM Plex Mono", size: 10 }, maxTicksLimit: 6 } }, y: { min: 0, suggestedMax: 80, grid: { color: "rgba(145,163,151,.09)" }, ticks: { color: "#6c7a70", font: { family: "IBM Plex Mono", size: 10 } } } } }
    });
    return () => chartInstance.current?.destroy();
  }, [chartPoints]);

  const navItems = useMemo(() => [{ name: "Overview", icon: Activity }, { name: "Threat intel", icon: ShieldAlert }, { name: "Model health", icon: Cpu }], []);

  // Compute live percentages from actual data
  const normalPct = packets.length ? Math.round((packets.filter(p => p.classification === "Normal").length / packets.length) * 1000) / 10 : 84.6;
  const anomPct = Math.round((100 - normalPct) * 10) / 10;

  if (activeSection !== "Overview") return <AuxiliaryView activeSection={activeSection} setActiveSection={setActiveSection} connected={connected} packets={packets} threats={threats} health={health} />;

  return <div className="soc-shell">
    <aside className="sidebar">
      <div className="brand"><img src="/manus-storage/signal-room-sentinel_222b9f60.png" alt="Signal Room sentinel" /><div><strong>signal<span>/</span>room</strong><small>THREAT SENSING GRID</small></div></div>
      <div className="rail-label">WORKSPACE</div>
      <nav>{navItems.map(({ name, icon: Icon }) => <button key={name} onClick={() => setActiveSection(name)} className={activeSection === name ? "nav-active" : ""}><Icon size={17} /><span>{name}</span>{name === "Threat intel" && <b>{String(threats.length).padStart(2, "0")}</b>}</button>)}</nav>
      <div className="sidebar-foot"><div className="rail-label">SYSTEM STATUS</div><div className="system-status"><span className="status-dot" /> <div><strong>{connected && streamMode === "sse" ? "Pipeline active" : "All systems nominal"}</strong><small>{connected && streamMode === "sse" ? `Dual engine v2.0 · ${health?.sse_clients ?? 0} client(s)` : "Model v1.0.4 · 99.2% uptime"}</small></div></div><div className="build-stamp">SIH26145 / LOCAL NODE<br />UNIDIRECTIONAL IP ANALYSIS</div></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div><div className="top-brand"><img src="/manus-storage/signal-room-sentinel_222b9f60.png" alt="" /><span>signal<span>/</span>room</span><b>SR-01</b></div><div className="eyebrow"><span className="live-pip" /> LIVE OPERATIONS / {activeSection.toUpperCase()}</div><h1>Threat detection <em>at the edge.</em></h1></div><div className="top-actions"><div className={`connection-pill ${connected ? "is-connected" : "is-offline"}`}><Wifi size={14} /> {streamMode === "sse" && connected ? "Pipeline connected" : streamMode === "sse" ? "Connecting…" : "Demo fallback"}</div><button className="icon-button" aria-label="Notifications"><Bell size={17} /><span className="notification-dot" /></button><div className="operator"><span>OP</span><div><strong>Operator</strong><small>SIH / SOC-01</small></div></div></div></header>
      <section className="control-strip"><div className="stream-copy"><span className="signal-bars"><i/><i/><i/><i/></span><div><strong>Inbound traffic listener</strong><small>One-way packet telemetry · {streamMode === "demo" ? "local simulation" : streamMode === "stress" ? "stress test mode" : "DDoS ML Pipeline SSE"}</small></div></div><div className="control-actions"><button className="quiet-button" onClick={() => setStreamMode("stress")}><ShieldAlert size={14} /> Run Stress Test</button><button className="quiet-button" onClick={() => setStreamMode(streamMode === "demo" ? "sse" : "demo")}><Zap size={14} /> {streamMode === "demo" ? "Connect ML pipeline" : "Use demo mode"}</button><button className={`pause-button ${paused ? "paused" : ""}`} onClick={() => setPaused(!paused)}>{paused ? "Resume stream" : "Pause stream"}</button></div></section>
      <section className="kpi-grid"><div className="kpi-card"><div className="kpi-top"><span>FLOWS ANALYZED</span><Database size={16} /></div><strong>{formatNumber(total)}</strong><div className="kpi-foot"><span className="positive">+{((packets.length / Math.max(total, 1)) * 100).toFixed(1)}%</span><span>{streamMode === "sse" ? "Zeek flow pipeline" : "playback records"}</span></div></div><div className="kpi-card"><div className="kpi-top"><span>AVG. AI CONFIDENCE</span><Gauge size={16} /></div><strong>{avgConfidence}<sup>%</sup></strong><div className="kpi-foot"><span className="positive">+2.4%</span><span>model certainty</span></div></div><div className="kpi-card model-card"><div className="kpi-top"><span>MODEL STATUS</span><CircleDot size={16} /></div><strong className="model-live">{health?.model_loaded || streamMode === "demo" ? "READY" : "LOADING"}</strong><div className="kpi-foot"><span>{streamMode === "sse" ? "Dual Engine" : "Random Forest"}</span><span>{streamMode === "sse" ? "IsoForest + RF + SHAP (Zeek)" : "5 features / v2.0.0"}</span></div></div></section>
      <section className="workspace-grid"><div className="panel chart-panel"><div className="panel-heading"><div><span className="section-kicker">01 / TRAFFIC VELOCITY</span><h2>Live traffic profile</h2></div><div className="chart-legend"><span><i className="legend-normal"/> Normal <b>{normalPct}%</b></span><span><i className="legend-threat"/> Anomalous <b>{anomPct}%</b></span></div></div><div className="instrument-ticks"><span>01 / IN</span><span>10:00</span><span>20:00</span><span>30:00</span><span>30 / OUT</span></div><div className="chart-meta"><span>PACKETS / SEC</span><span className="mono">LAST 30 MINUTES <ArrowUpRight size={12} /></span></div><div className="chart-wrap"><canvas ref={chartRef} /></div></div><aside className="panel incident-panel"><div className="panel-heading"><div><span className="section-kicker">02 / INCIDENT DIGEST</span><h2>Threat pulse</h2></div><span className="count-badge">{String(threats.length).padStart(2, "0")}</span></div><div className="threat-summary"><div className="summary-number">{threats.filter(t => t.severity === "critical").length}<span>critical</span></div><div className="summary-number warning-number">{threats.filter(t => t.severity === "warning").length}<span>warning</span></div><div className="summary-spark"><span /><span /><span /><span /><span /><span /><span /></div></div><div className="incident-list">{threats.slice(0, 4).map((threat, index) => <div className="incident-item" key={`${threat.timestamp}-${index}`}><div className={`incident-icon ${threat.severity}`}><AlertTriangle size={14} /></div><div><strong>{threat.threat_type}</strong><small>{threat.source_ip} · {threat.dst_ip ? `→ ${threat.dst_ip}` : `port ${threat.target_port}`}</small></div><time>{index === 0 ? "now" : `${index * 2}m`}</time></div>)}</div><button className="view-all" onClick={() => setActiveSection("Threat intel")}>View threat intelligence <ArrowUpRight size={14} /></button></aside></section>
      <section className="panel log-panel"><div className="panel-heading log-heading"><div><span className="section-kicker">03 / STREAM INSPECTION</span><h2>Threat log</h2></div><div className="log-tools"><span className="table-status"><span className="status-dot" /> {streamMode === "sse" && connected ? "Receiving from ML pipeline" : "Receiving packets"}</span><button className="filter-button">ALL EVENTS <span>⌄</span></button></div></div><div className="table-scroll"><table><thead><tr><th>EVENT TIME</th><th>SOURCE IP</th><th>{streamMode === "sse" ? "DEST IP" : "TARGET PORT"}</th><th>THREAT TYPE</th><th>AI CONFIDENCE</th><th>SEVERITY</th></tr></thead><tbody>{threats.map((threat, index) => <tr key={`${threat.timestamp}-${index}`}><td className="mono bright-time" onClick={() => setSelectedPacket(threat)}>{formatTime(threat.timestamp)}</td><td className="mono ip-cell">{threat.source_ip}</td><td className="mono bright-port" onClick={() => setSelectedPacket(threat)}>{streamMode === "sse" ? (threat.dst_ip ?? threat.target_port) : threat.target_port}</td><td className="class-cell" onClick={() => setSelectedPacket(threat)}><span className={`type-marker ${threat.severity}`} /><span className={`attack-badge ${threat.threat_type.includes("DoS") || threat.threat_type.includes("DDoS") || threat.threat_type.includes("SYN") ? "dos" : "recon"}`}>{threat.threat_type}</span></td><td><div className="confidence-cell"><div className="progress-track"><span style={{ width: `${threat.confidence}%` }} /></div><strong>{threat.confidence}%</strong></div></td><td><span className={`severity ${threat.severity}`}>{threat.severity === "critical" ? "CRITICAL" : "WARNING"}</span></td></tr>)}</tbody></table></div></section>{selectedPacket && <div className="inspector-backdrop" onClick={() => setSelectedPacket(null)}><aside className="inspector-drawer" onClick={event => event.stopPropagation()}><div className="inspector-head"><div><span className="section-kicker">{selectedPacket.evidence ? "VERDICT INSPECTOR / ML PIPELINE" : "PACKET INSPECTOR / RAW"}</span><h2>{selectedPacket.threat_type}</h2></div><button className="close-inspector" onClick={() => setSelectedPacket(null)}>×</button></div><p className="inspector-lede">{selectedPacket.evidence ? `Dual-engine verdict for ${selectedPacket.dst_ip ?? selectedPacket.source_ip}. Anomaly score: ${(selectedPacket.anomaly_score ?? 0).toFixed(3)}, classifier probability: ${(selectedPacket.classifier_probability ?? 0).toFixed(3)}.` : `Replay record ${selectedPacket.source_ip} → destination node. Metadata is displayed exactly as received from the playback engine.`}</p><div className="raw-grid"><div><span>{selectedPacket.evidence ? "ANOMALY SCORE" : "PACKET SIZE"}</span><strong>{selectedPacket.evidence ? (selectedPacket.anomaly_score ?? 0).toFixed(3) : `${selectedPacket.packet_size} B`}</strong></div><div><span>{selectedPacket.evidence ? "CLASSIFIER PROB." : "TCP FLAGS"}</span><strong>{selectedPacket.evidence ? (selectedPacket.classifier_probability ?? 0).toFixed(3) : (selectedPacket.protocol === "UDP" ? "—" : "SYN")}</strong></div><div><span>{selectedPacket.evidence ? "FLOW ID" : "TTL"}</span><strong>{selectedPacket.evidence ? (selectedPacket.flow_id ?? "—") : "64"}</strong></div><div><span>{selectedPacket.evidence ? "DST IP" : "MAC ADDRESS"}</span><strong>{selectedPacket.evidence ? (selectedPacket.dst_ip ?? "—") : "02:42:ac:11:00:10"}</strong></div><div><span>TARGET PORT</span><strong>{selectedPacket.target_port}</strong></div><div><span>{selectedPacket.evidence ? "THREAT CLASS" : "PAYLOAD ENTROPY"}</span><strong>{selectedPacket.evidence ? selectedPacket.threat_type : selectedPacket.payload_entropy.toFixed(2)}</strong></div></div><EvidenceGrid evidence={selectedPacket.evidence} /><div className="inspector-foot"><span className="status-dot" /> MODEL DECISION: {selectedPacket.classification.toUpperCase()} / {selectedPacket.confidence}%</div></aside></div>}<footer className="footer"><span>© 2026 SIGNAL ROOM / SIH26145 PROTOTYPE</span><span><span className="status-dot" /> {streamMode === "sse" && connected ? `ML PIPELINE · ${health?.sse_clients ?? 0} SSE CLIENT(S)` : "MODEL INFERENCE LATENCY 42ms"}</span></footer>
    </main>
  </div>;
}
