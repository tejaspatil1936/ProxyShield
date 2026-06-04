# ProxyShield

A self-hosted Layer-7 reverse proxy, written from scratch in Go, that learns each client's normal traffic pattern and automatically throttles anomalies.

## Overview

ProxyShield sits in front of a backend application and inspects every request before it is forwarded. Instead of relying only on fixed rate-limit thresholds, it profiles each device over a rolling window and tightens automatically when a client's traffic spikes far above its own learned baseline — on top of a more conventional set of L7 defenses (WAF signatures, honeypot traps, IP blacklisting, a circuit breaker, and an optional response cache).

The proxy core (`proxyshield-core/`) is a single Go binary with **zero external dependencies** — everything is built on the standard library. The repository also includes a full-stack demo, **KeyVault** (`demo-apikeys/`), an API-key-management app that ProxyShield protects, complete with a built-in attack simulator for exercising every defense live.

**Scope.** This is an educational / homelab-grade L7 application proxy. It defends against HTTP floods, brute-force login attempts, scraping/scanner probing, per-client/per-endpoint abuse, and common SQLi/XSS/high-entropy payloads. It is **not** a volumetric DDoS solution — stopping network-layer floods is a capacity/edge problem that no single self-hosted box can solve. For a production-grade signature WAF, the project's own docs suggest pairing or replacing the hand-rolled rules with [OWASP Coraza](https://coraza.io/) + the Core Rule Set. The adaptive per-device baseline is the part of this project that isn't just a reimplementation of well-known techniques.

> The name "ProxyShield" collides with existing products, including a registered trademark in the DDoS-mitigation space. The project's own README flags this as something to resolve (rename, or a trademark/domain search) before it grows beyond a personal/educational project.

## Features

- **Adaptive rate limiting** — learns a per-device baseline request rate over a rolling 5-minute window (thirty 10-second buckets) and applies an increasing penalty, up to a hard block, when a device's current-bucket rate exceeds a configurable multiple of its own baseline
- **Rate limiting** — token bucket and sliding-window algorithms, configurable per path + method
- **Device fingerprinting** — SHA-256 hash of IP + User-Agent + Accept-Language + Accept-Encoding, used as the tracking key everywhere instead of raw IP, so multiple devices behind one NAT/Wi-Fi IP aren't lumped together
- **WAF** — regex-based SQL injection and XSS signature detection across the path, query string, headers, and body; inputs are repeatedly URL-decoded and unicode-escape-decoded before matching so percent-encoded or `\uXXXX`-obfuscated payloads can't slip past a literal-text pattern
- **Shannon-entropy anomaly detection** — flags high-entropy (e.g. base64-encoded) request bodies above a configurable threshold; deliberately does not exempt binary content types other than genuine `multipart/form-data` uploads
- **Honeypots** — configurable trap URLs (`/admin`, `/.env`, `/wp-login.php`, ...) that trigger an automatic, time-limited device ban on the first hit, matched case-insensitively
- **IP blacklist** — static config-defined IPs plus runtime device bans (from honeypots), with a background sweep that evicts expired bans
- **Trusted-proxy `X-Forwarded-For` resolution** — fail-closed by default: the header is ignored unless the direct peer is itself in a configured `trusted_proxies` CIDR list, preventing an attacker from spoofing a fresh identity per request
- **Circuit breaker** — lock-free, atomic CLOSED → OPEN → HALF_OPEN state machine that stops sending traffic to a failing backend and admits bounded probe requests during recovery
- **Throttle** — graduated response delays as a client approaches its limit, instead of an immediate hard block
- **Response cache** — opt-in, per-path TTL cache for GET/HEAD; never serves or stores credentialed (Authorization/Cookie) requests, responses that set cookies, 4xx responses, or `Vary`'d responses
- **TLS** — optional HTTPS termination directly on the proxy listener
- **Hot reload** — the config file is watched and changes are applied without a restart
- **Real-time dashboard** — Server-Sent-Events-driven live view of traffic, blocks, and bans, with an optional bearer-token gate
- **Prometheus metrics** — a `/metrics` endpoint in text exposition format, reusing the same counters the dashboard already tracks
- **Built-in benchmark mode** — `--benchmark` load-tests the running configuration and prints a results table

## Tech Stack

| Category | Technology |
|---|---|
| Backend (core proxy) | Go 1.21, standard library only (`net/http`, `net/http/httputil`) — no third-party Go modules |
| Backend (demo app) | Node.js, Express 4, `cors` |
| Frontend (demo app) | React 18, Vite 5 |
| DevOps | Docker (multi-stage build), Railway (`railway.json`), Vercel (frontend hosting), GoReleaser (`.goreleaser.yml`) |
| Observability | Server-Sent Events dashboard, Prometheus text exposition (`/metrics`) |

## Architecture

Every incoming request passes through a single handler (`proxy/server.go`) that resolves the trustworthy client IP, enforces a max body size, then runs an ordered middleware chain before deciding whether to serve from cache, reject via the circuit breaker, or forward to the backend:

```
request
  │
  ▼
extractIP()            — trust XFF only from configured trusted_proxies CIDRs
  │
  ▼
fingerprint            — SHA-256(IP + UA + Accept-Language + Accept-Encoding)
  │
  ▼
ip-blacklist            ─┐
waf                       │  each middleware can short-circuit
honeypot                  │  the chain by writing a response
rate-limiter               │  and returning "blocked"
adaptive                  │
throttle                 ─┘
  │
  ▼
headers / cache check   — serve from ResponseCache on a hit
  │
  ▼
circuit breaker         — reject immediately if backend is OPEN
  │
  ▼
httputil.ReverseProxy    — forward to backend_url, capture status
  │
  ▼
cache store (if eligible) + event bus publish (stats / dashboard)
```

The middleware chain is built once from `config.Middlewares` and only rebuilt when the config pointer changes (hot reload), rather than on every request. An internal event bus fans out `RequestReceived` / `RequestForwarded` / `RequestBlocked` / `IPBanned` / `CacheHit` events to two independent consumers: the stats collector behind `/stats` and `/metrics`, and the SSE broker behind `/events`. The dashboard runs as a second HTTP server (`dashboard_port`) inside the same process.

## Project Structure

```
proxyshield/
├── proxyshield-core/            # The Go reverse proxy (main project)
│   ├── cmd/proxyshield/         # Entry point, CLI flags (--config, --benchmark, --verbose)
│   ├── internal/
│   │   ├── config/              # JSON config loading, validation, hot-reload watcher
│   │   ├── event/                # Channel-based pub/sub event bus
│   │   ├── logger/               # Structured JSON logger
│   │   ├── algorithm/            # Token bucket, sliding window, Shannon entropy
│   │   ├── reqctx/               # Shared per-request context type
│   │   ├── proxy/                # HTTP server, reverse-proxy forwarder, trusted-IP resolution
│   │   ├── middleware/            # WAF, blacklist, honeypot, rate limiter, adaptive, throttle, cache, circuit breaker
│   │   └── dashboard/             # SSE broker, stats collector, Prometheus exposition, static dashboard UI
│   ├── benchmark/                # Built-in self-benchmark
│   ├── config.json / config.production.json
│   └── honeypots.json
├── demo-apikeys/                 # "KeyVault" — a demo app ProxyShield protects
│   ├── backend/                  # Express API (in-memory data, HS256 JWT auth)
│   ├── frontend/                 # React + Vite dashboard UI, incl. a live Attack Tester
│   └── proxy-config.json
├── deploy/                       # Railway + Vercel deployment guide and start script
├── Dockerfile                    # Multi-stage build: Go binary + Node backend in one image
└── railway.json
```

## Getting Started

### Prerequisites

- Go 1.21+ (to build/run `proxyshield-core`)
- Node.js and npm (only needed for the `demo-apikeys` app)

### Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `PORT` | `proxyshield-core/cmd/proxyshield/main.go` | If set, overrides `server.listen_port`; the dashboard is bound to `PORT + 1`. Set automatically by Railway. |
| `BACKEND_PORT` | `demo-apikeys/backend/server.js` | Port the KeyVault backend listens on (default `3000`). |
| `FRONTEND_URL` | `demo-apikeys/backend/server.js` | Added to the CORS allow-list alongside the local dev origins. |
| `JWT_SECRET` | `demo-apikeys/backend/server.js` | HMAC secret for signing/verifying the demo's JWTs. Falls back to an insecure development default if unset — must be set in any real deployment. |

### Run locally

Proxy only:

```bash
cd proxyshield-core
go build -o proxyshield ./cmd/proxyshield/
./proxyshield --config config.json
```

Full demo (proxy + Express backend + React frontend):

```bash
cd demo-apikeys
./start.sh
# App:       http://localhost:5173
# Dashboard: http://localhost:9091   (set dashboard.auth_token in config to protect it)
# Login:     admin@apikeys.dev / admin123   (demo credential — not for production)
```

`start.sh` builds the Go binary automatically if it isn't present, then starts the backend, the proxy, and the Vite dev server together.

### Build

```bash
# Local binary
cd proxyshield-core && go build -o proxyshield-core ./cmd/proxyshield/

# Multi-platform release build (linux/darwin/windows, amd64/arm64) via GoReleaser
goreleaser release --snapshot --clean
```

The combined Docker image (`Dockerfile`) builds the Go binary in a `golang:1.21-alpine` stage, then copies it plus the KeyVault backend into a `node:18-alpine` runtime stage, and starts both via `deploy/start.sh` — this is the image Railway builds from `railway.json`.

### Tests

The proxy core has 68 Go test functions across every internal package — config validation, trusted-proxy CIDR/XFF resolution, both rate-limiting algorithms, entropy, the WAF's encoding-evasion cases, the circuit breaker's full state machine, honeypot/blacklist bans, safe-caching rules, the event bus, and the stats/Prometheus endpoints:

```bash
cd proxyshield-core
go test -race ./...
```

## Usage

Configuration lives in a single JSON file (`config.json`). Key sections:

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
  "rate_limits": [
    { "path": "/login", "method": "POST", "limit": 5, "window_seconds": 60, "algorithm": "sliding_window", "throttle_enabled": true }
  ],
  "security": { "block_sql_injection": true, "block_xss": true, "entropy_threshold": 5.5, "max_body_bytes": 1048576, "blacklisted_ips": [] },
  "honeypots": [{ "path": "/admin", "ban_minutes": 30 }],
  "adaptive": { "enabled": true, "spike_multiplier": 3.0, "learning_requests": 20, "decay_per_bucket": 0.15 },
  "dashboard": { "enabled": true, "max_events": 1000, "auth_token": "" }
}
```

`trusted_proxies` is empty by default, so `X-Forwarded-For` is ignored and the direct peer IP is used. Set it to your load balancer / platform edge CIDRs so the real client IP is recovered without opening a spoofing hole. Honeypot paths can also be loaded from an external file via `honeypot_file` (either an array of `{path, ban_minutes}` objects or a plain array of path strings).

Other run modes:

```bash
./proxyshield --config config.json --verbose        # debug logging
./proxyshield --benchmark --requests 10000 --concurrency 100
./proxyshield --version
```

The KeyVault demo's **Attack Tester** (bottom-right button in the UI) fires seven live attack simulations — brute force, SQL injection, XSS, a honeypot probe, a high-entropy encoded body, rapid key-creation spam, and a rate-limit header check — while the dashboard shows each one being blocked in real time.

## API Documentation

### ProxyShield operator API (dashboard process, `dashboard_port`)

All routes below are gated by `dashboard.auth_token` when it is set (pass via `Authorization: Bearer <token>` or `?token=`); with no token configured they are public.

| Method | Path | Description |
|---|---|---|
| GET | `/` , `/dashboard` | Serves the static real-time dashboard UI |
| GET | `/stats` | Current counters as JSON: total/forwarded/blocked requests, blocks by threat type, requests-per-second, active bans, uptime |
| GET | `/events` | Server-Sent Events stream of live proxy events |
| GET | `/metrics` | Prometheus text exposition (`proxyshield_requests_total`, `proxyshield_forwarded_total`, `proxyshield_blocked_total`, `proxyshield_blocked_by_type_total{threat=...}`, `proxyshield_active_bans`, `proxyshield_requests_per_second`, `proxyshield_uptime_seconds`) |

### KeyVault demo API (`demo-apikeys/backend`, behind the proxy)

All routes except `/api/login`, `/api/health`, and `/api/scan` require a `Bearer` JWT obtained from login.

| Method | Path | Description |
|---|---|---|
| POST | `/api/login` | Authenticates the demo admin user, returns a signed JWT |
| GET | `/api/keys` | Lists API keys (secrets never included) |
| GET | `/api/keys/search?q=` | Case-insensitive name search over keys |
| GET | `/api/keys/:id` | Fetches one key |
| POST | `/api/keys` | Creates a key; the plaintext secret is returned exactly once |
| DELETE | `/api/keys/:id` | Revokes a key |
| POST | `/api/keys/:id/rotate` | Rotates a key's secret; new plaintext returned exactly once |
| GET | `/api/keys/:id/usage` | Hourly usage series for one key |
| GET | `/api/usage/overview` | Aggregate usage stats across all keys |
| GET | `/api/health` | Health check (used by Railway's `healthcheckPath`) |
| POST | `/api/scan` | No-op endpoint with no configured rate limit, used by the Attack Tester to demonstrate the WAF entropy check in isolation |

## Design Decisions

- **Adaptive baseline instead of a fixed threshold.** `AdaptiveTracker` keeps a 5-minute rolling history of 10-second request-count buckets per device, and only starts enforcing after a configurable learning period (`learning_requests`). A spike is defined relative to that device's own historical average, not a global number, and the resulting penalty decays gradually per bucket rather than resetting instantly — so a burst produces graduated backoff instead of an on/off switch.
- **Fail-closed `X-Forwarded-For` trust.** `X-Forwarded-For` is honored only when the direct TCP peer is itself inside a configured `trusted_proxies` CIDR; otherwise the header is attacker-controlled and is ignored outright. The reverse-proxy forwarder deliberately uses `httputil.ReverseProxy`'s `Rewrite` hook instead of the older `Director`, specifically because `Director` would leave Go's automatic XFF-appending behavior in place, tacking the raw peer address onto whatever value the proxy sets.
- **Device fingerprint, not raw IP, as the tracking key.** Rate limiting, adaptive profiling, and bans key off a SHA-256 hash of IP + User-Agent + Accept-Language + Accept-Encoding wherever a fingerprint is available, so that multiple devices behind one NAT/Wi-Fi IP aren't penalized together.
- **WAF evasion resistance over raw signature matching.** Before running the SQLi/XSS regexes, request data is repeatedly percent-decoded (up to three passes) and `\uXXXX` JSON-unicode-decoded, so an attacker can't dodge a literal-text pattern with `%3Cscript%3E` or `<script>`. The entropy check deliberately does not exempt binary content types other than genuine `multipart/form-data`, since `image/*` or `application/octet-stream` is trivial for an attacker to set on a raw body to bypass entropy scanning on a non-upload API endpoint.
- **Cache correctness over cache-everything.** The response cache refuses to store or serve anything carrying `Authorization`/`Cookie`, anything the backend marked `Set-Cookie`, any 4xx/5xx status, and anything with a `Vary` header other than `Accept-Encoding` — because a method+URI-keyed cache can't safely represent per-user or content-negotiated responses.
- **Lock-free circuit breaker.** The circuit breaker's CLOSED/OPEN/HALF_OPEN state machine is implemented entirely with `sync/atomic` fields rather than a mutex, and bounds the number of probe requests admitted while in HALF_OPEN so a recovering backend isn't immediately hit with full traffic.
- **Zero external Go dependencies.** The entire proxy core is built on the standard library — `net/http`, `net/http/httputil`, `regexp`, `crypto/sha256` — with no third-party modules to audit or version.

## Future Improvements

- The project's own docs note that the hand-rolled WAF regex signatures are not a substitute for a production rule engine; pairing with [OWASP Coraza](https://coraza.io/) + the Core Rule Set is suggested for anything beyond homelab use.
- On Railway, only the single `$PORT` the proxy listens on is routed publicly — the dashboard (`$PORT + 1`) is not reachable at a public URL there, so it can currently only be viewed by running the proxy locally or deploying to a platform that exposes two ports.
- The WAF's entropy check currently only exempts `multipart/form-data`; a documented code comment already flags that legitimate binary-upload routes would need per-path exemptions rather than a blanket content-type skip.
- The project name collides with an existing trademark in the DDoS-mitigation space, which the maintainers have flagged as worth resolving before this grows past a personal project.

