@echo off
echo =========================================
echo Starting Cyber Threat SOC Test Environment
echo =========================================

echo.
echo [Step 1] Generating playback data...
cd /d f:\ddos_ml_pipeline\frontend
python backend/generate_pcap.py --count 300 --output backend/data/playback.csv

echo.
echo [Step 2] Training ML model...
python backend/train_model.py --data backend/data/playback.csv

echo.
echo [Step 3] Starting FastAPI Backend (Port 8000)...
start "FastAPI Backend" cmd /k "cd /d f:\ddos_ml_pipeline\frontend && uvicorn backend.main:app --reload --reload-dir backend --port 8000"

echo.
echo [Step 4] Starting React Frontend (Port 3000)...
start "React Frontend" cmd /k "cd /d f:\ddos_ml_pipeline\frontend && npm install --legacy-peer-deps && npm run dev"

echo.
echo =========================================
echo Both servers are starting in new windows!
echo   - Backend : http://localhost:8000/health
echo   - Frontend: http://localhost:3000
echo =========================================
echo.
echo Wait ~30 seconds, then open http://localhost:3000 in your browser.
pause
