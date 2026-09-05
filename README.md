# DDoS ML Pipeline & SOC Dashboard

This repository contains the complete, unified Cyber Threat SOC prototype. It consists of two distinct components:
1. **`backend/`**: The FastAPI server running the ML pipeline and Scapy packet sniffer.
2. **`frontend/`**: The React UI dashboard that visualizes the pipeline's verdicts.

## How to Run

You will need two separate terminal windows.

### 1. Boot the Backend (FastAPI + Scapy)
Open a terminal and navigate to the `backend` folder:
```bash
cd backend
python api_server.py
```
*Note: Ensure your environment has the required Python dependencies installed (FastAPI, uvicorn, scapy, scikit-learn, joblib, pandas).*

### 2. Boot the Frontend (React + Vite)
Open a second terminal and navigate to the `frontend` folder:
```bash
cd frontend
npm install
npm run dev
```
*Note: Ensure you have Node.js and npm installed.*

### 3. Verify
Open your browser and navigate to `http://localhost:3000`. The dashboard will start in a clean slate waiting for live operations. Ensure your network adapter is properly connected for the physical attack.
