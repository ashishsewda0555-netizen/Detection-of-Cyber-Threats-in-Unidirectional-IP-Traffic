import os
import time
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP

# --- CONFIGURATION ---
# Hardcoded to the isolated USB Ethernet network
VICTIM_IP = "192.168.100.2"
CSV_FILE = "live_stream.csv"
INTERFACE = "Ethernet 3"

print(f"🛡️ Starting Live AI Sentinel on {VICTIM_IP}...")
print(f"Listening on interface: {INTERFACE}")
print("Capturing 5-second windows. Press Ctrl+C to stop.\n")

while True:
    try:
        # Sniff traffic for exactly 5 seconds strictly on the USB adapter
        packets = sniff(
            iface=INTERFACE,
            timeout=5,
            filter=f"ip dst {VICTIM_IP} or ip src {VICTIM_IP}",
        )
        
        if not packets:
            continue

        total_captured = len(packets)

        # Initialize feature counters
        fwd_pkts, bwd_pkts = 0, 0
        syn_flags, ack_flags = 0, 0
        packet_sizes = []
        unique_ips = set()

        # Parse packets to extract Hackathon features
        for pkt in packets:
            if IP in pkt:
                packet_sizes.append(len(pkt))
                
                # Directionality (Forward = Inbound to Victim)
                if pkt[IP].dst == VICTIM_IP:
                    fwd_pkts += 1
                    unique_ips.add(pkt[IP].src)
                else:
                    bwd_pkts += 1

                # TCP Flags
                if TCP in pkt:
                    flags = pkt[TCP].flags
                    if 'S' in flags: syn_flags += 1
                    if 'A' in flags: ack_flags += 1

        # Free memory immediately after parsing
        del packets

        # Map to the exact feature names your ML model expects
        features = {
            "Dst_IP": VICTIM_IP,
            "flow_rate": (fwd_pkts + bwd_pkts) / 5.0, 
            "packet_rate": (fwd_pkts + bwd_pkts) / 5.0,
            "fwd_bwd_ratio": fwd_pkts / (bwd_pkts + 1),
            "unique_src_count": len(unique_ips),
            "syn_flag_sum": syn_flags,
            "ack_flag_sum": ack_flags,
            "syn_ack_ratio": syn_flags / (ack_flags + 1),
            "avg_packet_size": np.mean(packet_sizes) if packet_sizes else 0,
            "packet_size_std": np.std(packet_sizes) if packet_sizes else 0
        }

        # Save to CSV instantly so Streamlit can read it
        df = pd.DataFrame([features])
        write_header = not os.path.exists(CSV_FILE)
        df.to_csv(CSV_FILE, mode='a', header=write_header, index=False)
        
        print(f"[{time.strftime('%X')}] Window captured: {total_captured} packets | {len(unique_ips)} source IPs")

    except KeyboardInterrupt:
        print("\nStopped by user.")
        break
    except Exception as e:
        print(f"[{time.strftime('%X')}] ERROR in window (skipped): {e}")
        continue