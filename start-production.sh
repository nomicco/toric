#!/bin/bash
set -e

DATA_DIR=${DATA_DIR:-/data}
ADMIN_PORT=${ADMIN_PORT:-44121}
APP_PORT=${APP_PORT:-44122}
API_PORT=${API_PORT:-3000}
APP_ID=${APP_ID:-toric}
BOOTSTRAP_URL=${BOOTSTRAP_URL:-https://bootstrap.holo.host}
SIGNAL_URL=${SIGNAL_URL:-wss://dev-test-bootstrap2.holochain.org}
RELAY_URL=${RELAY_URL:-wss://dev-test-bootstrap2.holochain.org}

mkdir -p "$DATA_DIR"

echo "Using pre-built happ..."

# Write conductor config with actual env var values
cat > /tmp/conductor-config.yaml << EOF
---
data_root_path: $DATA_DIR
keystore:
  type: lair_server_in_proc
admin_interfaces:
  - driver:
      type: websocket
      port: $ADMIN_PORT
      allowed_origins: "*"
network:
  bootstrap_url: "$BOOTSTRAP_URL"
  signal_url: "$SIGNAL_URL"
  relay_url: "$RELAY_URL"
  signal_allow_plain_text: true
  danger_allow_non_tls_relay: true
db_sync_strategy: Fast
EOF

echo "Starting conductor..."
NIX_LD=/nix/store/km4g87jxsqxvcq344ncyb8h1i6f3cqxh-glibc-2.40-218/lib/ld-linux-x86-64.so.2
echo "" | "$NIX_LD" /usr/local/bin/holochain --piped -c /tmp/conductor-config.yaml &
CONDUCTOR_PID=$!

# Wait for admin port
echo "Waiting for conductor..."
for i in $(seq 1 30); do
  node -e "
    const net = require('net');
    const c = net.connect($ADMIN_PORT, '127.0.0.1');
    c.on('connect', () => process.exit(0));
    c.on('error', () => process.exit(1));
  " 2>/dev/null && break
  sleep 2
done
echo "Conductor ready"

echo "Installing happ..."
APP_ID=$APP_ID APP_PORT=$APP_PORT ADMIN_PORT=$ADMIN_PORT node scripts/install-happ.js

echo "Starting API..."
ADMIN_PORT=$ADMIN_PORT APP_PORT=$APP_PORT API_PORT=$API_PORT APP_ID=$APP_ID \
  node api/index.js &
API_PID=$!

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Toric node running"
echo "API: http://localhost:$API_PORT"
echo "Bootstrap: $BOOTSTRAP_URL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

trap "kill $CONDUCTOR_PID $API_PID 2>/dev/null" EXIT
wait $CONDUCTOR_PID