"""
Phase 2 — PCAP to Windowed Features (5-Second Time Buckets)
============================================================
Reads raw PCAP files directly with Scapy and groups packets into
5-second wall-clock windows grouped by Dst_IP — exactly mirroring
how live_capture.py works in production.

Replaces the old 30-row chunking in 01_build_windowed_features.py.

Usage:
    python pcap_to_features.py

Input:  spoofed_flood_01.pcap, benign_deep_01.pcap
Output: windowed_features.csv
"""

import os
import struct
import math
import time
from collections import defaultdict
import numpy as np
import pandas as pd

# --- CONFIGURATION ---
PCAP_FILES = {
    "spoofed_flood_01.pcap": "ddos_spoofed_syn_flood",
    "benign_deep_01.pcap": "benign",
}
OUTPUT_CSV = "windowed_features.csv"
WINDOW_SECONDS = 5  # Must match live_capture.py

# Ethernet + IP + TCP header offsets (for raw binary parsing)
ETH_HEADER_LEN = 14
IP_PROTO_OFFSET = 9
IP_SRC_OFFSET = 12
IP_DST_OFFSET = 16
IP_IHL_OFFSET = 0
TCP_SRC_PORT_OFFSET = 0
TCP_DST_PORT_OFFSET = 2
TCP_FLAGS_OFFSET = 13

PROTO_TCP = 6


def entropy(counts_dict):
    """Shannon entropy from a dict of {item: count}."""
    total = sum(counts_dict.values())
    if total == 0:
        return 0.0
    probs = [c / total for c in counts_dict.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def parse_pcap_packets(filepath):
    """
    Generator that yields (timestamp_sec, pkt_bytes) from a PCAP or PCAPNG file.
    Uses raw binary I/O for .pcap, falls back to Scapy's RawPcapNgReader for .pcapng.
    """
    # Peek at magic to determine format
    with open(filepath, 'rb') as f:
        magic = f.read(4)

    if magic == b'\x0a\x0d\x0d\x0a':
        # PCAPNG format — use Scapy's reader
        print("  (Detected pcapng format, using Scapy reader)")
        from scapy.utils import RawPcapNgReader
        with RawPcapNgReader(filepath) as reader:
            for pkt_data, pkt_meta in reader:
                # pcapng stores timestamps as (tshigh << 32 | tslow) / tsresol
                raw_ts = (pkt_meta.tshigh << 32) | pkt_meta.tslow
                tsresol = pkt_meta.tsresol if pkt_meta.tsresol else 1_000_000
                timestamp = raw_ts / tsresol
                yield timestamp, pkt_data
    else:
        # Standard PCAP format — fast binary parser
        with open(filepath, 'rb') as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return

            if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
                endian = '<'
            elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
                endian = '>'
            else:
                raise ValueError(f"Unknown PCAP magic: {magic.hex()}")

            while True:
                pkt_header = f.read(16)
                if not pkt_header or len(pkt_header) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    f"{endian}IIII", pkt_header
                )
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                timestamp = ts_sec + ts_usec / 1_000_000.0
                yield timestamp, pkt_data


def find_ip_start(pkt_bytes):
    """
    Determine where the IP header starts in the packet.
    Returns the offset, or -1 if not an IPv4 packet.
    """
    if len(pkt_bytes) < 20:
        return -1

    # Try Ethernet frame first (EtherType at offset 12-13)
    if len(pkt_bytes) >= ETH_HEADER_LEN + 20:
        ethertype = struct.unpack("!H", pkt_bytes[12:14])[0]
        if ethertype == 0x0800:
            return ETH_HEADER_LEN

    # Try raw IP (version nibble = 4 at offset 0)
    version = (pkt_bytes[0] >> 4) & 0xF
    if version == 4:
        return 0

    return -1


def extract_packet_info(pkt_bytes, victim_ip_bytes_set):
    """
    Parse raw packet bytes (Ethernet or raw IP) and extract:
    (src_ip, dst_ip, dst_port, pkt_len, is_syn, is_ack, is_inbound, is_tcp)

    Returns None if not an IPv4 packet.
    """
    ip_start = find_ip_start(pkt_bytes)
    if ip_start < 0:
        return None

    if len(pkt_bytes) < ip_start + 20:
        return None

    ip_header_byte = pkt_bytes[ip_start + IP_IHL_OFFSET]
    ip_header_len = (ip_header_byte & 0x0F) * 4
    protocol = pkt_bytes[ip_start + IP_PROTO_OFFSET]

    src_ip = pkt_bytes[ip_start + IP_SRC_OFFSET: ip_start + IP_SRC_OFFSET + 4]
    dst_ip = pkt_bytes[ip_start + IP_DST_OFFSET: ip_start + IP_DST_OFFSET + 4]
    pkt_len = len(pkt_bytes)

    is_inbound = dst_ip in victim_ip_bytes_set
    is_syn = False
    is_ack = False
    dst_port = 0

    if protocol == PROTO_TCP:
        tcp_start = ip_start + ip_header_len
        if len(pkt_bytes) >= tcp_start + 14:
            dst_port = struct.unpack("!H", pkt_bytes[tcp_start + TCP_DST_PORT_OFFSET: tcp_start + TCP_DST_PORT_OFFSET + 2])[0]
            flags_byte = pkt_bytes[tcp_start + TCP_FLAGS_OFFSET]
            is_syn = bool(flags_byte & 0x02)
            is_ack = bool(flags_byte & 0x10)

    # Convert IPs to string for grouping
    src_ip_str = f"{src_ip[0]}.{src_ip[1]}.{src_ip[2]}.{src_ip[3]}"
    dst_ip_str = f"{dst_ip[0]}.{dst_ip[1]}.{dst_ip[2]}.{dst_ip[3]}"

    return {
        "src_ip": src_ip_str,
        "dst_ip": dst_ip_str,
        "dst_port": dst_port,
        "pkt_len": pkt_len,
        "is_syn": is_syn,
        "is_ack": is_ack,
        "is_inbound": is_inbound,
        "is_tcp": protocol == PROTO_TCP,
    }


def flush_window(accumulator, window_start_ts, label):
    """
    Convert accumulated packet stats for one (dst_ip, time_bucket) into
    feature rows matching live_capture.py's output.
    
    If a single 5-second bucket has a massive number of packets (e.g., 250k 
    from a compressed capture), it gets split into sub-windows of ~PACKETS_PER_SUBWINDOW 
    to produce realistic training samples.
    """
    PACKETS_PER_SUBWINDOW = 5000  # Realistic packets per 5-sec live window during attack
    
    rows = []
    for dst_ip, stats in accumulator.items():
        total_pkts = stats["fwd"] + stats["bwd"]
        if total_pkts == 0:
            continue

        pkt_sizes = stats["pkt_sizes"]
        src_ip_counts = stats["src_ip_counts"]
        
        # Determine how many sub-windows to create
        n_subwindows = max(1, total_pkts // PACKETS_PER_SUBWINDOW)
        
        if n_subwindows == 1:
            # Normal case: just one window
            rows.append(_build_feature_row(
                dst_ip, window_start_ts, stats, pkt_sizes, src_ip_counts, label, total_pkts
            ))
        else:
            # Split oversized bucket into realistic sub-windows
            # Each sub-window gets a proportional slice of the data
            sub_size = total_pkts // n_subwindows
            src_ips_list = list(src_ip_counts.keys())
            
            for sub_idx in range(n_subwindows):
                start = sub_idx * sub_size
                end = start + sub_size if sub_idx < n_subwindows - 1 else len(pkt_sizes)
                sub_pkt_sizes = pkt_sizes[start:end]
                sub_total = len(sub_pkt_sizes)
                
                # Proportionally split counts
                ratio = sub_total / total_pkts
                sub_fwd = int(stats["fwd"] * ratio)
                sub_bwd = sub_total - sub_fwd
                sub_syn = int(stats["syn"] * ratio)
                sub_ack = int(stats["ack"] * ratio)
                
                # Each sub-window gets a proportional slice of unique IPs
                n_sub_ips = max(1, int(len(src_ips_list) * ratio))
                ip_start = sub_idx * n_sub_ips
                sub_src_ips = src_ips_list[ip_start: ip_start + n_sub_ips]
                sub_src_counts = {ip: src_ip_counts.get(ip, 1) for ip in sub_src_ips}
                
                sub_stats = {
                    "fwd": sub_fwd, "bwd": sub_bwd,
                    "syn": sub_syn, "ack": sub_ack,
                    "dst_ports": stats["dst_ports"],
                }
                
                rows.append(_build_feature_row(
                    dst_ip, window_start_ts + sub_idx * WINDOW_SECONDS,
                    sub_stats, sub_pkt_sizes, sub_src_counts, label, sub_total
                ))
    return rows


def _build_feature_row(dst_ip, window_start_ts, stats, pkt_sizes, src_ip_counts, label, total_pkts):
    """Build a single feature dict row."""
    return {
        "Dst_IP": dst_ip,
        "Window_Start": pd.Timestamp.fromtimestamp(window_start_ts, tz="UTC"),
        "flow_rate": total_pkts / WINDOW_SECONDS,
        "packet_rate": total_pkts / WINDOW_SECONDS,
        "fwd_bwd_ratio": stats["fwd"] / (stats["bwd"] + 1),
        "unique_src_count": len(src_ip_counts),
        "src_ip_entropy": entropy(src_ip_counts),
        "syn_flag_sum": stats["syn"],
        "ack_flag_sum": stats["ack"],
        "syn_ack_ratio": stats["syn"] / (stats["ack"] + 1),
        "avg_packet_size": np.mean(pkt_sizes) if pkt_sizes else 0.0,
        "packet_size_std": np.std(pkt_sizes) if len(pkt_sizes) > 1 else 0.0,
        "unique_dst_ports": len(stats["dst_ports"]),
        "Label": label,
    }


def make_empty_accumulator():
    """Create a fresh per-dst-ip stats accumulator."""
    return defaultdict(lambda: {
        "fwd": 0,
        "bwd": 0,
        "syn": 0,
        "ack": 0,
        "pkt_sizes": [],
        "src_ip_counts": defaultdict(int),
        "dst_ports": set(),
    })


def process_pcap(filepath, label):
    """
    Read a PCAP file and produce windowed feature rows using 5-second
    time-based bucketing.
    """
    print(f"\n--- Processing: {filepath} (label={label}) ---")
    if not os.path.exists(filepath):
        print(f"  [SKIP] File not found: {filepath}")
        return []

    file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
    print(f"  File size: {file_size_mb:.1f} MB")

    all_rows = []
    accumulator = make_empty_accumulator()
    current_window_start = None
    packet_count = 0
    window_count = 0

    # First pass: detect victim IP (most common dst IP)
    print("  Pass 1: Detecting victim IP...")
    dst_ip_counter = defaultdict(int)
    sample_count = 0
    for ts, pkt_bytes in parse_pcap_packets(filepath):
        ip_start = find_ip_start(pkt_bytes)
        if ip_start < 0:
            continue
        if len(pkt_bytes) < ip_start + 20:
            continue
        dst_ip = pkt_bytes[ip_start + IP_DST_OFFSET: ip_start + IP_DST_OFFSET + 4]
        dst_ip_str = f"{dst_ip[0]}.{dst_ip[1]}.{dst_ip[2]}.{dst_ip[3]}"
        dst_ip_counter[dst_ip_str] += 1
        sample_count += 1
        if sample_count >= 100000:
            break

    if not dst_ip_counter:
        print("  [SKIP] No IP packets found.")
        return []

    victim_ip = max(dst_ip_counter, key=dst_ip_counter.get)
    victim_ip_parts = [int(x) for x in victim_ip.split(".")]
    victim_ip_bytes = bytes(victim_ip_parts)
    victim_ip_bytes_set = {victim_ip_bytes}
    print(f"  Detected victim IP: {victim_ip} ({dst_ip_counter[victim_ip]:,} hits in sample)")

    # Second pass: extract features
    print("  Pass 2: Extracting 5-second windowed features...")
    t_start = time.time()

    for ts, pkt_bytes in parse_pcap_packets(filepath):
        info = extract_packet_info(pkt_bytes, victim_ip_bytes_set)
        if info is None:
            continue

        # Determine the 5-second window this packet belongs to
        window_start = int(ts // WINDOW_SECONDS) * WINDOW_SECONDS

        # If we've moved to a new window, flush the old one
        if current_window_start is not None and window_start != current_window_start:
            rows = flush_window(accumulator, current_window_start, label)
            all_rows.extend(rows)
            window_count += len(rows)
            accumulator = make_empty_accumulator()

        current_window_start = window_start

        # Accumulate stats grouped by dst_ip
        dst_ip = info["dst_ip"]
        stats = accumulator[dst_ip]

        if info["is_inbound"]:
            stats["fwd"] += 1
            stats["src_ip_counts"][info["src_ip"]] += 1
        else:
            stats["bwd"] += 1

        if info["is_syn"]:
            stats["syn"] += 1
        if info["is_ack"]:
            stats["ack"] += 1

        stats["pkt_sizes"].append(info["pkt_len"])
        if info["dst_port"] > 0:
            stats["dst_ports"].add(info["dst_port"])

        packet_count += 1
        if packet_count % 500000 == 0:
            elapsed = time.time() - t_start
            print(f"    ...processed {packet_count:,} packets ({elapsed:.1f}s)")

    # Flush the final window
    if current_window_start is not None:
        rows = flush_window(accumulator, current_window_start, label)
        all_rows.extend(rows)
        window_count += len(rows)

    elapsed = time.time() - t_start
    print(f"  Done: {packet_count:,} packets -> {window_count} windows ({elapsed:.1f}s)")
    return all_rows


def main():
    print("=" * 60)
    print("  Phase 2 — PCAP to Windowed Features (5-Second Buckets)")
    print("=" * 60)

    all_rows = []
    for pcap_file, label in PCAP_FILES.items():
        rows = process_pcap(pcap_file, label)
        all_rows.extend(rows)

    if not all_rows:
        print("\nERROR: No feature rows were generated. Check your PCAP files.")
        return

    df = pd.DataFrame(all_rows)
    df.to_csv(OUTPUT_CSV, index=False)

    print(f"\n{'=' * 60}")
    print(f"  SUCCESS: {len(df)} windows saved to {OUTPUT_CSV}")
    print(f"{'=' * 60}")
    print(f"\nLabel distribution:")
    print(df["Label"].value_counts())
    print(f"\nFeature columns: {list(df.columns)}")
    print(f"\nSample row:")
    print(df.iloc[0])


if __name__ == "__main__":
    main()
