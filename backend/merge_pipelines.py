import os
import pandas as pd
import numpy as np

def generate_unified_features():
    print("Loading Scapy high-frequency metrics...")
    scapy_csv = os.path.join(os.path.dirname(__file__), "..", "Archive 2", "windowed_features.csv")
    
    if not os.path.exists(scapy_csv):
        print(f"Error: {scapy_csv} not found.")
        return
        
    df = pd.read_csv(scapy_csv)
    
    print(f"Loaded {len(df)} rows from Scapy pipeline.")
    print("Simulating Zeek flow-path metadata extraction (5-tuple & exfiltration metrics)...")
    
    # Initialize rng
    rng = np.random.default_rng(42)
    
    # Assign Mock Zeek Features based on Label
    orig_bytes = np.zeros(len(df))
    resp_bytes = np.zeros(len(df))
    protos = []
    
    for i, row in df.iterrows():
        label = row['Label']
        
        # Base protocol
        protos.append(rng.choice(["tcp", "udp"]) if label == "benign" else "tcp")
        
        if label == "benign":
            # Normal web traffic: highly variable
            o_b = int(rng.normal(1200, 800))
            r_b = int(rng.normal(8500, 5000))
        elif label == "ddos_spoofed_syn_flood":
            # SYN flood with partial handshakes (more bytes)
            o_b = int(rng.normal(90, 25))
            r_b = int(rng.normal(30, 20))
        elif label == "port_scan":
            # Port scans are small probes
            o_b = int(rng.normal(800, 200))
            r_b = int(rng.normal(800, 200))
        elif label == "ddos_unknown_variant":
            # Some overlap with heavy benign
            o_b = int(rng.normal(1500, 700))
            r_b = int(rng.normal(1500, 700))
        else:
            # Exfiltration (overlaps with benign occasionally)
            o_b = int(rng.normal(80000, 30000))
            r_b = int(rng.normal(150, 100))
            
        orig_bytes[i] = max(0, o_b)
        resp_bytes[i] = max(0, r_b)
        
    df['orig_bytes'] = orig_bytes
    df['resp_bytes'] = resp_bytes
    df['exfiltration_ratio'] = df['orig_bytes'] / (df['resp_bytes'] + 1.0)
    
    df['id.orig_h'] = [f"10.0.{rng.integers(1,255)}.{rng.integers(1,255)}" for _ in range(len(df))]
    df['id.resp_h'] = df['Dst_IP']
    df['id.orig_p'] = rng.integers(1024, 65535, size=len(df))
    df['id.resp_p'] = rng.choice([80, 443, 53, 22, 3306], size=len(df))
    df['proto'] = protos
    
    # Unified Feature Matrix Schema (13 features + metadata)
    final_cols = [
        # Metadata
        'id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p', 'proto', 'Window_Start', 'Label',
        # Scapy Fast-Path (TCP/Rates)
        'flow_rate', 'packet_rate', 'fwd_bwd_ratio', 'unique_src_count', 'src_ip_entropy',
        'syn_flag_sum', 'ack_flag_sum', 'syn_ack_ratio', 'avg_packet_size', 'packet_size_std', 'unique_dst_ports',
        # Zeek Flow-Path (Bytes/Exfil)
        'orig_bytes', 'resp_bytes', 'exfiltration_ratio'
    ]
    
    unified_df = df[final_cols]
    output_path = os.path.join(os.path.dirname(__file__), "unified_features.csv")
    unified_df.to_csv(output_path, index=False)
    
    print(f"Merged unified pipeline schema saved to: {output_path}")
    print(f"Unified features count: {len(final_cols) - 7}") # minus metadata
    print("Schema preview:")
    print(unified_df.head(2).to_dict(orient='records'))
    
if __name__ == "__main__":
    generate_unified_features()
