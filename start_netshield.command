#!/bin/bash
# ------------------------------------------------------------------
#  NetShield AI - 1-Click Desktop Launcher for macOS / Linux
# ------------------------------------------------------------------
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "======================================================="
echo "        🛡️ NetShield AI - Security Dashboard           "
echo "======================================================="
echo "Starting NetShield Backend Server..."

# Kill any running api_server instances
pkill -9 -f api_server.py 2>/dev/null || true

# Launch backend in background
python3 backend/api_server.py &
SERVER_PID=$!

echo "Waiting for server startup..."
sleep 2

# Open in default browser
if command -v open &> /dev/null; then
    open "http://localhost:8000"
elif command -v xdg-open &> /dev/null; then
    xdg-open "http://localhost:8000"
fi

echo "======================================================="
echo "NetShield AI is live at: http://localhost:8000"
echo "Press Ctrl+C in this window to stop NetShield."
echo "======================================================="

wait $SERVER_PID
