# Dual-Engine AI DDoS Sentinel (Real-Time Detection & XAI)

This repository contains the source code for a real-time DDoS detection pipeline, built for the **Smart India Hackathon**. It uses a Dual-Engine Machine Learning architecture to detect both known volumetric attacks and unknown zero-day anomalies "on the fly."

## 🧠 Architecture Overview

The pipeline evaluates network traffic in **5-second rolling windows** to calculate packet rates and flow dynamics, ensuring near-real-time detection without storing massive PCAP files.

*   **Engine 1: Isolation Forest (Zero-Day Discovery)**
    *   An unsupervised anomaly detector trained exclusively on normal traffic. It flags any traffic that deviates from the normal human baseline as a "Zero-Day Anomaly."
*   **Engine 2: Random Forest (Sub-Type Classification)**
    *   A robust supervised classifier trained on historical DDoS data. If an anomaly is flagged, it categorizes the specific attack type (e.g., High-Volume SYN Flood).
*   **XAI Layer: TreeSHAP**
    *   Provides eXplainable AI (XAI) by instantly showing exactly *which* network features (like `syn_flag_sum` or `packet_rate`) caused the model to trigger the alert.

---

## 🚀 Live Demo Setup Guide

This guide assumes you are simulating an attack from a Windows Attacker PC to a Windows Victim PC over a Local Wi-Fi Hotspot.

### 1. Network Preparation
1. Create a Mobile Hotspot on a phone.
2. Connect both the **Victim PC** and the **Attacker PC** to this hotspot.
3. The Victim PC (running this code) will automatically be assigned the standard Windows Hotspot IP: `192.168.137.1`.
4. **CRITICAL:** Ensure Windows Defender Firewall is **OFF** on the Victim PC, otherwise Windows will silently drop the attack packets before Python can see them.

### 2. Environment Setup
Install the required dependencies on the Victim PC:
```cmd
pip install pandas numpy scikit-learn scapy streamlit shap joblib
```

### 3. Starting the Sentinel (Victim PC)
You must start the components in this exact order using two separate terminals.

**Terminal 1 (Must be Run as Administrator):**
Because sniffing raw network sockets requires admin privileges on Windows, open a Command Prompt as Administrator, navigate to the project folder, and run:
```cmd
cd /d F:\ddos_ml_pipeline
python live_capture.py
```
*(Note: `live_capture.py` includes built-in crash protection to ensure the capture loop survives massive packet floods).*

**Terminal 2 (Normal Terminal):**
Open a second terminal, navigate to the project folder, and start the dashboard:
```cmd
cd /d F:\ddos_ml_pipeline
streamlit run dashboard.py
```
Once the browser opens, click the red **Start Live Network Monitor** button. Do not refresh the browser page after clicking this.

### 4. Launching the Attack (Attacker PC)
From the Attacker PC, use Nmap's `nping` tool to launch a volumetric SYN flood against the Victim PC.

Run this command in an Administrator terminal on the Attacker PC:
```cmd
nping --tcp -p 80 --flags syn --rate 10000 -c 50000 192.168.137.1
```
*   `--rate 10000`: Sends 10,000 packets per second.
*   `-c 50000`: Limits the attack to 50,000 packets (prevents freezing the Victim PC).

Within 5 seconds, the Streamlit dashboard on the Victim PC will turn red, displaying a Critical Alert with the exact confidence score and the SHAP features that triggered the detection.

---

## 🛠️ File Structure
*   `live_capture.py`: Scapy packet sniffer that groups traffic into 5-second windows and extracts mathematical features.
*   `scorer.py`: The inference engine that loads the Joblib model and SHAP explainer to generate verdicts.
*   `dashboard.py`: The real-time Streamlit UI that polls `live_stream.csv` and visualizes the attacks.
*   `ddos_dual_engine_model.joblib`: The pre-trained ML bundle.
*   `.gitignore`: Prevents uploading large CSV datasets and Python cache files to GitHub.
