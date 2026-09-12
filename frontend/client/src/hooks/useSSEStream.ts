/**
 * useSSEStream — Connects the React frontend to the DDoS ML pipeline's
 * FastAPI SSE endpoint (`/api/stream`), translating the scorer's verdict
 * schema into the frontend's TrafficPacket type.
 *
 * Features:
 *   - Reconnection with exponential backoff (1s → 2s → 4s → … → 30s)
 *   - Late-join catch-up via `/api/history`
 *   - Health polling via `/api/health`
 *   - Graceful fallback flag when the backend is unreachable
 */

import { useCallback, useEffect, useRef, useState } from "react";

// ── Types ──────────────────────────────────────────────────────────────

/** Raw verdict emitted by the ML pipeline's scorer.score_window(). */
export interface PipelineVerdict {
  flow_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  proto?: string;
  anomaly_score: number;
  classifier_probability: number;
  is_alert: boolean;
  threat_class?: string;
  confidence?: number;
  severity?: "critical" | "high" | "medium";
  evidence?: Record<string, number>;
}

/** Shape the frontend already renders everywhere. */
export interface TrafficPacket {
  timestamp: string;
  source_ip: string;
  target_port: number;
  packet_size: number;
  protocol: string;
  payload_entropy: number;
  threat_type: string;
  classification: "Normal" | "Threat";
  confidence: number;
  severity: "critical" | "warning" | "normal";
  // Extended fields from the real ML pipeline
  anomaly_score?: number;
  classifier_probability?: number;
  evidence?: Record<string, number>;
  flow_id?: string;
  dst_ip?: string;
}

/** Health response from /api/health. */
export interface HealthStatus {
  status: string;
  model_loaded: boolean;
  sse_clients: number;
  stats: {
    total_windows: number;
    critical_alerts: number;
    high_alerts: number;
    medium_alerts: number;
    port_scans: number;
    benign_windows: number;
  };
}

// ── Helpers ────────────────────────────────────────────────────────────

const THREAT_LABEL_MAP: Record<string, string> = {
  ddos_syn_flood: "SYN Flood DDoS",
  ddos_spoofed_syn_flood: "SYN Flood DDoS",
  ddos_volumetric: "Volumetric DDoS",
  ddos_unknown_variant: "Unknown DDoS Variant",
  port_scan: "Port Scan",
  exfiltration: "Data Exfiltration",
  benign: "Clean flow",
};

function mapSeverity(
  s?: "critical" | "high" | "medium",
): "critical" | "warning" | "normal" {
  if (s === "critical") return "critical";
  if (s === "high" || s === "medium") return "warning";
  return "normal";
}

/**
 * Translate a pipeline verdict into the frontend's TrafficPacket shape.
 * Fields that don't exist on the verdict are given sensible defaults so
 * every downstream component renders without null-checks.
 */
function verdictToPacket(v: PipelineVerdict & { classification?: string }): TrafficPacket {
  const isAlert = v.is_alert ?? (v.classification === "Threat") ?? false;
  const rawConf = v.confidence ?? v.classifier_probability ?? 0;
  // Pipeline confidence is 0-1; frontend expects 0-100
  const confidence =
    rawConf <= 1 ? Math.round(rawConf * 100) : Math.round(rawConf);

  return {
    timestamp: v.timestamp ?? new Date().toISOString(),
    source_ip: v.src_ip ?? v.dst_ip ?? "unknown",
    target_port: 0, // Zeek flows carry port in id.resp_p — not mapped here
    packet_size: 0, // Not available from flow-level features
    protocol: v.proto ?? "TCP",
    payload_entropy: v.anomaly_score ?? 0,
    threat_type: isAlert
      ? THREAT_LABEL_MAP[v.threat_class ?? ""] ?? v.threat_class ?? "Threat"
      : "Clean flow",
    classification: isAlert ? "Threat" : "Normal",
    confidence: confidence || (isAlert ? 92 : 97),
    severity: isAlert ? mapSeverity(v.severity) : "normal",
    // Extended
    anomaly_score: v.anomaly_score,
    classifier_probability: v.classifier_probability,
    evidence: v.evidence,
    flow_id: v.flow_id,
    dst_ip: v.dst_ip,
  };
}

// ── Hook ───────────────────────────────────────────────────────────────

interface UseSSEStreamOptions {
  /** Whether the hook should actively connect. */
  enabled: boolean;
}

interface UseSSEStreamReturn {
  /** Packets received since the hook mounted. */
  packets: TrafficPacket[];
  /** Threat-classified packets only (most recent first). */
  threats: TrafficPacket[];
  /** Whether we have an active SSE connection. */
  connected: boolean;
  /** Latest health status from /api/health. */
  health: HealthStatus | null;
  /** If true the backend is unreachable and the caller should use demo mode. */
  fallback: boolean;
}

const MAX_PACKETS = 200;
const MAX_THREATS = 24;
const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;

export function useSSEStream({
  enabled,
}: UseSSEStreamOptions): UseSSEStreamReturn {
  const [packets, setPackets] = useState<TrafficPacket[]>([]);
  const [threats, setThreats] = useState<TrafficPacket[]>([]);
  const [connected, setConnected] = useState(false);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [fallback, setFallback] = useState(false);

  const retriesRef = useRef(0);
  const esRef = useRef<EventSource | null>(null);

  // Resolve the base URL.  During Vite dev the proxy rewrites /api/* so
  // we can just use a relative path.  In production the env var is baked in.
  const baseUrl = (
    import.meta.env.VITE_API_BASE_URL ?? ""
  ).replace(/\/+$/, "");

  // ── Fetch health ──
  const fetchHealth = useCallback(async () => {
    try {
      const res = await fetch(`${baseUrl}/api/health`);
      if (res.ok) {
        const data = (await res.json()) as HealthStatus;
        setHealth(data);
        return true;
      }
    } catch {
      /* backend down */
    }
    return false;
  }, [baseUrl]);

  // ── Fetch history (late-join catch-up) ──
  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch(`${baseUrl}/api/history`);
      if (!res.ok) return;
      const data = (await res.json()) as { verdicts: PipelineVerdict[] };
      if (data.verdicts?.length) {
        const mapped = data.verdicts.map(verdictToPacket);
        setPackets((cur) => [...cur, ...mapped].slice(-MAX_PACKETS));
        const newThreats = mapped.filter((p) => p.classification === "Threat");
        if (newThreats.length) {
          setThreats((cur) =>
            [...newThreats.reverse(), ...cur].slice(0, MAX_THREATS),
          );
        }
      }
    } catch {
      /* history endpoint optional */
    }
  }, [baseUrl]);

  // ── SSE connection lifecycle ──
  useEffect(() => {
    if (!enabled) {
      esRef.current?.close();
      esRef.current = null;
      setConnected(false);
      return;
    }

    let cancelled = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    async function connect() {
      // Probe health first — if backend is down, bail early.
      const alive = await fetchHealth();
      if (!alive) {
        setFallback(true);
        setConnected(false);
        // Schedule retry with backoff
        const delay = Math.min(
          RECONNECT_BASE_MS * 2 ** retriesRef.current,
          RECONNECT_MAX_MS,
        );
        retriesRef.current += 1;
        if (!cancelled) {
          reconnectTimer = setTimeout(connect, delay);
        }
        return;
      }

      setFallback(false);
      retriesRef.current = 0;

      // Catch up on history before opening the live stream
      await fetchHistory();

      const es = new EventSource(`${baseUrl}/api/stream`);
      esRef.current = es;

      es.onopen = () => {
        if (!cancelled) setConnected(true);
      };

      es.onmessage = (event) => {
        if (cancelled) return;
        try {
          const verdict = JSON.parse(event.data) as PipelineVerdict;
          const packet = verdictToPacket(verdict);
          setPackets((cur) => [...cur.slice(-(MAX_PACKETS - 1)), packet]);
          if (packet.classification === "Threat") {
            setThreats((cur) => [packet, ...cur].slice(0, MAX_THREATS));
          }
        } catch {
          /* malformed event, skip */
        }
      };

      es.onerror = () => {
        es.close();
        esRef.current = null;
        if (cancelled) return;
        setConnected(false);
        const delay = Math.min(
          RECONNECT_BASE_MS * 2 ** retriesRef.current,
          RECONNECT_MAX_MS,
        );
        retriesRef.current += 1;
        reconnectTimer = setTimeout(connect, delay);
      };
    }

    connect();

    // Poll health every 15s while connected
    const healthInterval = setInterval(fetchHealth, 15_000);

    return () => {
      cancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      clearInterval(healthInterval);
      esRef.current?.close();
      esRef.current = null;
    };
  }, [enabled, baseUrl, fetchHealth, fetchHistory]);

  return { packets, threats, connected, health, fallback };
}
