# ProxyShield Core (Go)

High-performance reverse proxy and API gateway written in Go. Zero external dependencies — standard library only.

## Features

- **WAF**: SQL injection, XSS detection, Shannon entropy anomaly detection
- **Rate Limiting**: Token bucket + sliding window algorithms (per-IP, per-endpoint)
- **Honeypots**: Trap URLs that auto-ban scanners
- **IP Blacklist**: Static + runtime bans
- **Throttle**: Graduated delays without blocking
- **Hot Reload**: Config changes applied without restart
- **Dashboard**: Real-time SSE dashboard at `:9091`
- **Benchmark**: Built-in self-benchmark mode

## Build

```bash
go build -o proxyshield-core ./cmd/proxyshield/
```

Requires Go 1.21+. Zero external dependencies.

## Run

```bash
./proxyshield-core --config config.json
./proxyshield-core --config config.json --verbose
./proxyshield-core --benchmark --requests 10000 --concurrency 100
```

## Testing

```bash
go test ./...          # run the suite
go test -race ./...    # with the race detector (recommended)
go test -cover ./...   # with coverage
```

The suite covers the token bucket and sliding window limiters, Shannon entropy,
the WAF (including encoding/unicode evasion and the entropy Content-Type bypass),
the circuit-breaker state machine, IP blacklist/honeypot bans, safe response
caching, config validation and trusted-proxy CIDR parsing, the event bus, and the
trusted-proxy `X-Forwarded-For` resolution — with race coverage on the shared
rate-limit and stats state.

## Config

```json
{
  "server": {
    "listen_port": 9090,
    "backend_url": "http://localhost:8080",
    "dashboard_port": 9091
  },
  "middlewares": ["ip-blacklist", "waf", "honeypot", "rate-limiter", "throttle", "headers"],
  "rate_limits": [...],
  "security": {...},
  "honeypots": [...],
  "throttle": {...},
  "dashboard": { "enabled": true, "max_events": 1000 }
}
```

## Dashboard

Open `http://localhost:9091` while the proxy is running to see live traffic, blocked threats, and stats.

## Demo App

See `../demo-apikeys/` for the KeyVault demo — a full API Key Management Platform that shows ProxyShield protecting a real backend.

```bash
cd ../demo-apikeys && ./start.sh
```

## Architecture

```
proxyshield-core/
├── cmd/proxyshield/       # Entry point, CLI flags
├── internal/
│   ├── config/            # Config loading + hot-reload watcher
│   ├── event/             # Channel-based event bus
│   ├── logger/            # Structured JSON logger
│   ├── algorithm/         # Token bucket, sliding window, entropy
│   ├── reqctx/            # Shared per-request context type
│   ├── proxy/             # HTTP server + reverse proxy forwarder
│   ├── middleware/        # WAF, blacklist, honeypot, rate limiter, throttle
│   └── dashboard/         # SSE broker, stats collector, static dashboard
└── benchmark/             # Built-in self-benchmark
```

## Performance

The Go rewrite is designed for maximum throughput:
- Fixed-size circular array for sliding window (O(1) memory per IP)
- `sync.Map` for concurrent access to rate limit state
- Per-entry fine-grained mutex locking (not one global lock)
- Regex compiled once at startup
- `httputil.ReverseProxy` with connection pooling (100 idle conns)
- Non-blocking event publishing (events dropped vs. blocking proxy)
