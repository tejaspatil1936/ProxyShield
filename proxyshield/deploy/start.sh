#!/bin/bash
echo "Starting ProxyShield (production)..."

# Get port from Railway (or default 9090)
export PROXY_PORT="${PORT:-9090}"

# Start Express backend on localhost:3000 (hidden)
cd /app/backend
node server.js &
BACKEND_PID=$!
echo "Backend started on 127.0.0.1:3000"

# Wait for backend to be ready
sleep 2

# Update config with correct port
cd /app/proxy
sed -i "s/\"listen_port\": 9090/\"listen_port\": $PROXY_PORT/" config.json

# Start Go proxy in foreground
echo "Proxy starting on port $PROXY_PORT"
exec ./proxyshield-core --config config.json
