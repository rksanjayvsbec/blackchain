@echo off
TITLE NetShield AI Launcher
cls
echo =======================================================
echo         NetShield AI - Security Dashboard             
echo =======================================================
echo Starting NetShield Backend Server...

python backend\api_server.py

pause
