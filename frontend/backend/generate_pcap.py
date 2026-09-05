"""Generate a deterministic PCAP-like CSV and optional .pcap for the SIH26145 playback demo."""
from __future__ import annotations
import argparse, csv, random
from datetime import datetime, timedelta, timezone
from pathlib import Path


def make_row(index: int, start: datetime, kind: str) -> dict:
    if kind == "Volumetric DoS":
        src, dst, port, size, protocol, flags = "192.0.2.44", "10.0.0.10", 80, random.randint(1200, 1460), "TCP", "SYN"
        entropy, ttl, mac = 4.2, 51, "02:42:ac:11:00:44"
    elif kind == "Reconnaissance":
        src, dst, port, size, protocol, flags = "198.51.100.23", "10.0.0.10", 20 + (index % 20), random.randint(48, 110), "TCP", "SYN"
        entropy, ttl, mac = 2.8, 54, "02:42:cb:00:00:23"
    else:
        src, dst, port, size, protocol, flags = "10.1.4.22", "10.0.0.10", random.choice([53, 80, 443, 123]), random.randint(240, 980), random.choice(["TCP", "UDP"]), random.choice(["ACK", "PSH,ACK", ""])
        entropy, ttl, mac = round(random.uniform(2.0, 6.0), 3), 64, "02:42:0a:01:04:16"
    return {"timestamp": (start + timedelta(seconds=index)).isoformat(), "source_ip": src, "destination_ip": dst, "target_port": port, "packet_size": size, "protocol": protocol, "payload_entropy": entropy, "tcp_flags": flags, "ttl": ttl, "mac_address": mac, "attack_classification": kind, "label": 0 if kind == "Normal" else 1, "sequence": index}


def generate(count: int, output: Path, pcap_output: Path | None = None) -> None:
    random.seed(42)
    start = datetime.now(timezone.utc).replace(microsecond=0)
    fields = ["timestamp", "source_ip", "destination_ip", "target_port", "packet_size", "protocol", "payload_entropy", "tcp_flags", "ttl", "mac_address", "attack_classification", "label", "sequence"]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader()
        for i in range(count):
            kind = "Volumetric DoS" if 60 <= i < 110 else ("Reconnaissance" if 170 <= i < 205 else "Normal")
            writer.writerow(make_row(i, start, kind))
    if pcap_output:
        try:
            from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # type: ignore
            packets = []
            for i in range(min(count, 500)):
                row = make_row(i, start, "Volumetric DoS" if 60 <= i < 110 else ("Reconnaissance" if 170 <= i < 205 else "Normal"))
                layer = TCP(sport=40000 + i, dport=row["target_port"], flags=row["tcp_flags"] or "A") if row["protocol"] == "TCP" else UDP(sport=40000 + i, dport=row["target_port"])
                packets.append(Ether(src=row["mac_address"]) / IP(src=row["source_ip"], dst=row["destination_ip"], ttl=row["ttl"]) / layer / Raw(load=b"signal-room-demo"))
            wrpcap(str(pcap_output), packets)
            print(f"Wrote optional PCAP to {pcap_output}")
        except ImportError:
            print("Scapy not installed; CSV metadata remains the portable playback source.")
    print(f"Wrote {count:,} sequential packet records to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--count", type=int, default=300); parser.add_argument("--output", type=Path, default=Path("backend/data/playback.csv")); parser.add_argument("--pcap", type=Path, default=None); args = parser.parse_args(); generate(args.count, args.output, args.pcap)
