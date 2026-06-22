#!/bin/bash
# Starts the network and auto-launches APIs when conductors are ready

UI_PORT=""
ADMIN0=""
APP0=""
ADMIN1=""
APP1=""

echo "Starting Toric dev network..."
npm run start 2>&1 | while IFS= read -r line; do
  echo "$line"

  # Grab UI port
  if [[ "$line" =~ Local:.*http://localhost:([0-9]+) ]]; then
    UI_PORT="${BASH_REMATCH[1]}"
  fi

  # Grab conductor 0
  if [[ "$line" =~ Conductor\ launched\ \#\!0.*admin_port\":([0-9]+).*app_ports\":\[([0-9]+) ]]; then
    ADMIN0="${BASH_REMATCH[1]}"
    APP0="${BASH_REMATCH[2]}"
  fi

  # Grab conductor 1
  if [[ "$line" =~ Conductor\ launched\ \#\!1.*admin_port\":([0-9]+).*app_ports\":\[([0-9]+) ]]; then
    ADMIN1="${BASH_REMATCH[1]}"
    APP1="${BASH_REMATCH[2]}"
  fi

  # Once we have everything, launch APIs
  if [[ -n "$UI_PORT" && -n "$ADMIN0" && -n "$APP0" && -n "$ADMIN1" && -n "$APP1" ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Agent 0: http://localhost:${UI_PORT}/?api=3000"
    echo "Agent 1: http://localhost:${UI_PORT}/?api=3001"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    ADMIN_PORT=$ADMIN0 APP_PORT=$APP0 API_PORT=3000 APP_ID=toric node api/index.js &
    ADMIN_PORT=$ADMIN1 APP_PORT=$APP1 API_PORT=3001 APP_ID=toric node api/index.js &

    # Reset so we don't launch again
    ADMIN0=""
  fi
done