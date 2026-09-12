@echo off
echo =========================================
echo Starting DDoS Sentinel (Zeek Pipeline)
echo =========================================

echo.
echo [Step 1] Training ML model on Zeek features...
cd /d F:\PRJ_1\ddos_ml_pipeline\backend
python train_zeek_model.py

echo.
echo [Step 2] Starting FastAPI Backend (Port 8000)...
start "FastAPI Backend" cmd /k "cd /d F:\PRJ_1\ddos_ml_pipeline\backend && uvicorn api_server:app --reload --port 8000"

echo.
echo [Step 3] Starting React Frontend (Port 3000)...
start "React Frontend" cmd /k "cd /d F:\PRJ_1\ddos_ml_pipeline\frontend && npm install --legacy-peer-deps && npm run dev"

echo.
echo =========================================
echo Both servers are starting in new windows!
echo   - Backend : http://localhost:8000/api/health
echo   - Frontend: http://localhost:3000
echo =========================================
echo.
echo Wait ~30 seconds, then open http://localhost:3000 in your browser.
pause
