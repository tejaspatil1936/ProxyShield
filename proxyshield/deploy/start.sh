#!/bin/bash
set -e
echo "Starting ProxyShield (production)..."

# Start Express backend on 127.0.0.1:3000 (hidden from the internet)
cd /app/backend
node server.js &
echo "Backend started on 127.0.0.1:3000"

# Wait for backend to be ready
sleep 2

# Start the Go proxy in the foreground. It binds to $PORT automatically (the
# binary reads PORT and overrides listen_port), so no fragile config rewrite is
# needed — Railway sets PORT; locally it defaults to the config's 9090.
cd /app/proxy
echo "Proxy starting on port ${PORT:-9090}"
exec ./proxyshield-core --config config.json
