import pandas as pd
from scorer import score_window, feature_cols

def test_model_capabilities():
    print("==================================================")
    print("🛡️ Manual Verification of Dual-Engine DDoS Model 🛡️")
    print("==================================================\n")

    base_time = pd.Timestamp.now(tz="UTC")

    # 1. Benign Traffic
    print("--- 1. Testing Benign Traffic ---")
    benign = {
        "Dst_IP": "192.168.100.2", "Window_Start": base_time,
        "flow_rate": 2.0, "packet_rate": 2.0, "fwd_bwd_ratio": 1.0, 
        "unique_src_count": 1, "syn_flag_sum": 0, "ack_flag_sum": 2, 
        "syn_ack_ratio": 0.0, "avg_packet_size": 150.0, "packet_size_std": 20.0,
        "unique_dst_ports": 1
    }
    print(f"Result: {score_window(benign)}\n")

    # 2. Spoofed Source SYN Flood (Testing Phase 2 Fix #3)
    print("--- 2. Testing Spoofed-Source SYN Flood ---")
    spoofed = {
        "Dst_IP": "192.168.100.2", "Window_Start": base_time,
        "flow_rate": 5000.0, "packet_rate": 5000.0, "fwd_bwd_ratio": 5000.0, 
        "unique_src_count": 4800,  # High source entropy
        "syn_flag_sum": 5000, "ack_flag_sum": 0, 
        "syn_ack_ratio": 5000.0, "avg_packet_size": 60.0, "packet_size_std": 0.0,
        "unique_dst_ports": 1
    }
    print(f"Result: {score_window(spoofed)}\n")

    # 3. Port Scan (Testing Phase 2 Fix #4 - Parallel Flow)
    print("--- 3. Testing Port Scan Parallel Detector ---")
    port_scan = {
        "Dst_IP": "192.168.100.2", "Window_Start": base_time,
        "flow_rate": 50.0, "packet_rate": 50.0, "fwd_bwd_ratio": 1.0, 
        "unique_src_count": 1, "syn_flag_sum": 50, "ack_flag_sum": 50, 
        "syn_ack_ratio": 1.0, "avg_packet_size": 60.0, "packet_size_std": 0.0,
        "unique_dst_ports": 50  # Triggers parallel detector
    }
    print(f"Result: {score_window(port_scan)}\n")

    # 4. Zero-Day Anomaly (Testing Isolation Forest)
    print("--- 4. Testing Zero-Day Anomaly (Jumbo buffer payload) ---")
    zeroday = {
        "Dst_IP": "192.168.100.2", "Window_Start": base_time,
        "flow_rate": 1.0, "packet_rate": 1.0, "fwd_bwd_ratio": 1.0, 
        "unique_src_count": 1, "syn_flag_sum": 0, "ack_flag_sum": 1, 
        "syn_ack_ratio": 0.0, 
        "avg_packet_size": 1492.0,  # Massive packet size anomaly
        "packet_size_std": 0.0,
        "unique_dst_ports": 1
    }
    print(f"Result: {score_window(zeroday)}\n")

if __name__ == "__main__":
    test_model_capabilities()
