#!/bin/bash
# Usage: ./start-agents.sh 43997 44479 43837 44787 32959
# Args: admin0 app0 admin1 app1 ui_port

ADMIN0=$1
APP0=$2
ADMIN1=$3
APP1=$4
UI_PORT=${5:-32959}

echo "Starting Agent 0 API on port 3000..."
ADMIN_PORT=$ADMIN0 APP_PORT=$APP0 API_PORT=3000 node api/index.js &
PID0=$!

echo "Starting Agent 1 API on port 3001..."
ADMIN_PORT=$ADMIN1 APP_PORT=$APP1 API_PORT=3001 node api/index.js &
PID1=$!

echo ""
echo "Agent 0: http://localhost:${UI_PORT}/?api=3000"
echo "Agent 1: http://localhost:${UI_PORT}/?api=3001"
echo ""
echo "Press Ctrl+C to stop both"

trap "kill $PID0 $PID1" EXIT
wait