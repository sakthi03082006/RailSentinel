@echo off
echo ========================================================
echo   RailSentinel - Starting Laptop Webcam CCTV Ingest
echo ========================================================
python scripts\register_cctv.py
python -m ai.cctv.service --camera 0 --conf 0.35
pause
