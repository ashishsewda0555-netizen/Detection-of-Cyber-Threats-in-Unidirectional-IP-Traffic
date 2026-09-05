"""
mock_traffic_generator.py — UI/UX Testing Utility

This script simulates the Scapy sniffer for frontend developers.
It reads pre-computed feature windows from the training dataset and POSTs
them to the FastAPI backend. This allows UI developers to build and test
the React dashboard without needing root/admin privileges, raw sockets,
or actual network attacks.

Usage:
    1. Start the API: python api_server.py
    2. Start the mock generator: python mock_traffic_generator.py
    3. The React UI will now receive a rich stream of attacks and benign traffic.
"""

import time
import requests
import pandas as pd

API_SCORE_URL = "http://localhost:8000/api/score"
DATASET_PATH = "Archive 2/windowed_features.csv"

def main():
    print("🛡️  DDoS Sentinel — Mock Traffic Generator (UI/UX Testing)")
    print(f"   Target API : {API_SCORE_URL}")
    print(f"   Dataset    : {DATASET_PATH}")
    
    try:
        df = pd.read_csv(DATASET_PATH)
        print(f"   Loaded {len(df)} windows from dataset.\n")
    except FileNotFoundError:
        print(f"❌ Could not find {DATASET_PATH}. Are you in the project root?")
        return

    # Optional: shuffle or sample the dataframe to mix attacks and benign
    # We will just iterate through it.
    
    print("🚀 Starting mock stream (1 window per second). Press Ctrl+C to stop.")
    
    windows_sent = 0
    try:
        for idx, row in df.iterrows():
            features = row.to_dict()
            
            # Inject fake context if missing from the CSV
            features["Dst_IP"] = "192.168.100.2"
            features["Window_Start"] = str(pd.Timestamp.now(tz="UTC"))
            
            try:
                res = requests.post(API_SCORE_URL, json=features, timeout=2)
                if res.status_code == 200:
                    verdict = res.json()
                    is_alert = verdict.get("is_alert", False)
                    threat = verdict.get("threat_class", "benign")
                    icon = "🚨" if is_alert else "✅"
                    print(f"[{time.strftime('%X')}] POST {idx:04d} {icon} -> {threat}")
                else:
                    print(f"❌ API Error: {res.status_code}")
            except requests.ConnectionError:
                print("❌ Cannot connect to API. Is api_server.py running?")
                time.sleep(2)
                continue
                
            windows_sent += 1
            time.sleep(1) # Send 1 window per second for UI testing (faster than real-time 5s)
            
    except KeyboardInterrupt:
        print(f"\n🛑 Stopped. Sent {windows_sent} mock windows.")

if __name__ == "__main__":
    main()
