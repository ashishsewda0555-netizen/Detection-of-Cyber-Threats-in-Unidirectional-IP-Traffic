"""Generate labeled synthetic unidirectional IP traffic for SIH26145."""
from __future__ import annotations
import argparse, json, math, random
from datetime import datetime, timezone
from pathlib import Path

PROTOCOLS = ["TCP", "UDP", "ICMP"]
THREATS = ["ddos_spike", "port_scan", "malicious_payload"]

def entropy_for_payload(kind: str | None) -> float:
    if kind == "malicious_payload": return round(random.uniform(7.2, 8.0), 3)
    return round(random.uniform(2.0, 6.2), 3)

def packet(index: int, threat: str | None) -> dict:
    if threat == "ddos_spike":
        source, port, size, protocol = f"185.14.{random.randint(1,240)}.{random.randint(1,240)}", random.choice([80, 443, 8080]), random.randint(1200, 2400), random.choice(["UDP", "TCP"])
    elif threat == "port_scan":
        source, port, size, protocol = f"91.204.{random.randint(1,240)}.{random.randint(1,240)}", random.choice([22, 23, 3389, 445]), random.randint(40, 180), "TCP"
    elif threat == "malicious_payload":
        source, port, size, protocol = f"103.77.{random.randint(1,240)}.{random.randint(1,240)}", random.choice([445, 1433, 8443]), random.randint(900, 2200), "TCP"
    else:
        source, port, size, protocol = f"10.24.{random.randint(0,18)}.{random.randint(2,240)}", random.choice([53, 80, 123, 443]), random.randint(180, 1100), random.choice(PROTOCOLS)
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "source_ip": source, "target_port": port, "packet_size": size, "protocol": protocol, "payload_entropy": entropy_for_payload(threat), "threat_type": threat or "normal", "label": int(bool(threat)), "sequence": index}

def generate(count: int = 5000, output: Path = Path("backend/data/traffic.jsonl")) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as stream:
        for index in range(count):
            threat = random.choice(THREATS) if random.random() < 0.18 else None
            stream.write(json.dumps(packet(index, threat)) + "\n")
    print(f"Wrote {count:,} packets to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--count", type=int, default=5000); parser.add_argument("--output", type=Path, default=Path("backend/data/traffic.jsonl")); args = parser.parse_args(); random.seed(42); generate(args.count, args.output)
