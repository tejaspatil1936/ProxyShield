# Stage 1: Build Go binary
FROM golang:1.21-alpine AS go-builder
WORKDIR /app
COPY proxyshield-core/go.mod proxyshield-core/go.sum* ./
COPY proxyshield-core/ .
RUN go build -o proxyshield-core ./cmd/proxyshield/

# Stage 2: Final image with Node + Go binary
FROM node:18-alpine
RUN apk --no-cache add ca-certificates bash

# Copy Go binary and assets
WORKDIR /app/proxy
COPY --from=go-builder /app/proxyshield-core .
# Use the production config (backend on 127.0.0.1:3000, /api/* rate limits,
# trusted_proxies for the platform edge) — NOT the dev config.json.
COPY --from=go-builder /app/config.production.json ./config.json
COPY --from=go-builder /app/honeypots.json ./honeypots.json
COPY --from=go-builder /app/internal/dashboard/public ./internal/dashboard/public

# Copy backend
WORKDIR /app/backend
COPY demo-apikeys/backend/package*.json ./
RUN npm install --production
COPY demo-apikeys/backend/ .

# Copy start script
WORKDIR /app
COPY deploy/start.sh .
RUN chmod +x start.sh

EXPOSE 9090

CMD ["./start.sh"]
