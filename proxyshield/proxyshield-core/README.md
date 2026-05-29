# ProxyShield Core (Go)

High-performance reverse proxy and API gateway written in Go. Zero external dependencies — standard library only.

> **Scope:** an educational/homelab-grade **Layer-7** proxy. It handles HTTP
> floods, brute force, scraping, and per-client abuse — not volumetric DDoS. For
> a production signature WAF, pair it with [Coraza](https://coraza.io/) + CRS.

## Features

- **Adaptive rate limiting**: learns per-device baselines, auto-blocks spikes
- **Rate Limiting**: token bucket + sliding window (per-device, per-endpoint)
- **WAF**: SQLi/XSS signatures with percent-/unicode-decode; Shannon-entropy anomaly detection over header, query, and body
- **Honeypots**: trap URLs that auto-ban scanners (case-insensitive)
- **IP Blacklist**: static + runtime device bans, with expiry sweeping
- **Trusted-proxy XFF**: `X-Forwarded-For` honored only from configured upstream CIDRs (fail-closed)
- **Circuit breaker**: bounded HALF_OPEN probes protect a recovering backend
- **Throttle**: graduated delays without hard blocking
- **TLS**: optional HTTPS termination (`server.tls`)
- **Response cache**: opt-in, credential/Set-Cookie/Vary-aware
- **Hot Reload**: config changes applied without restart
- **Dashboard**: real-time SSE dashboard at `:9091`, optional `dashboard.auth_token`
- **Metrics**: Prometheus `/metrics`
- **Benchmark**: built-in self-benchmark mode

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
    "dashboard_port": 9091,
    "trusted_proxies": ["10.0.0.0/8"],
    "tls": { "enabled": false, "cert_file": "", "key_file": "" }
  },
  "middlewares": ["fingerprint", "ip-blacklist", "waf", "honeypot", "rate-limiter", "adaptive", "throttle", "headers", "cache"],
  "rate_limits": [...],
  "security": {...},
  "honeypots": [...],
  "throttle": {...},
  "dashboard": { "enabled": true, "max_events": 1000, "auth_token": "" },
  "adaptive": { "enabled": true, "spike_multiplier": 3.0, "learning_requests": 20, "decay_per_bucket": 0.15 }
}
```

> `trusted_proxies` is empty by default, which means `X-Forwarded-For` is ignored
> and the direct peer IP is used (fail-closed). Set it to your load balancer /
> platform edge CIDRs so the real client IP is recovered safely.

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
