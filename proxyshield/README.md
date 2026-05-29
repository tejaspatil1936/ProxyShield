# ProxyShield

A self-hosted **Layer-7 reverse proxy** written from scratch in Go (standard
library only, single binary) that learns each client's normal traffic pattern
and automatically throttles anomalies — pairing behavioral rate limiting with
honeypot auto-bans, a signature WAF, and per-endpoint limits.

## Scope (read this first)

ProxyShield is an **educational / homelab-grade L7 application proxy**. It
defends against application-layer abuse:

- HTTP request floods and brute-force login attempts
- Scraping and scanner probing (honeypot traps + auto-ban)
- Per-client / per-endpoint rate abuse
- Common SQLi / XSS payloads and high-entropy obfuscated bodies

It is **not** a volumetric DDoS solution — stopping network-layer floods is a
capacity/edge problem (Cloudflare-scale) and no single self-hosted box can do it.
For a production-grade signature WAF, pair or replace the hand-rolled rules with
[OWASP Coraza](https://coraza.io/) + the Core Rule Set. The genuinely uncommon
piece here is the **per-device adaptive baseline**: it learns each client's
normal rate and auto-tightens on spikes.

## Structure

- `proxyshield-core/` — the Go reverse proxy (main project)
- `demo-apikeys/` — "KeyVault", a demo app the proxy protects (includes a live attack tester)

## Quick Start

```bash
cd proxyshield-core
go build -o proxyshield ./cmd/proxyshield/
./proxyshield --config config.json
```

```bash
# Full demo (proxy + backend + frontend)
cd demo-apikeys
./start.sh
# App:       http://localhost:5173
# Dashboard: http://localhost:9091   (set dashboard.auth_token to protect it)
# Login:     admin@apikeys.dev / admin123   (demo credential — not for production)
```

## Features

- **Adaptive rate limiting** — learns per-device baselines, auto-blocks spikes
- **Rate limiting** — token bucket + sliding window, per-device, per-endpoint
- **WAF** — SQLi/XSS signatures with percent- and unicode-decode; Shannon-entropy anomaly detection (header, query, and body aware)
- **Honeypots** — trap URLs that auto-ban scanners (case-insensitive)
- **IP blacklist** — static config + runtime device bans, with expiry sweeping
- **Trusted-proxy `X-Forwarded-For`** — fail-closed by default; honored only from configured upstream CIDRs
- **Circuit breaker** — sheds load from a failing backend; bounded HALF_OPEN probes
- **Throttle** — graduated delays without hard blocking
- **TLS** — optional HTTPS termination on the proxy listener
- **Response cache** — opt-in, credential/Set-Cookie/Vary-aware (safe to enable)
- **Hot reload** — config changes applied without restart
- **Dashboard** — real-time SSE dashboard, optional token auth
- **Metrics** — Prometheus `/metrics` (zero-dependency exposition)
- **Benchmark** — `./proxyshield --benchmark`

## Security posture

- `X-Forwarded-For` is ignored unless the direct peer is in `server.trusted_proxies`.
- Server read/write/idle timeouts and backend dial/response timeouts guard against Slowloris and hung backends.
- The dashboard's `/stats`, `/events`, and `/metrics` can require a token (`dashboard.auth_token`); no wildcard CORS.
- The response cache never stores credentialed requests, `Set-Cookie`, 4xx, or `Vary`'d responses.

## Testing

```bash
cd proxyshield-core
go test -race ./...
```

## Docs

- [proxyshield-core/README.md](proxyshield-core/README.md) — Go proxy architecture, config, and usage
- [demo-apikeys/README.md](demo-apikeys/README.md) — KeyVault demo setup and attack tester
- [deploy/README.md](deploy/README.md) — Railway + Vercel deployment guide

## Note on the name

"ProxyShield" collides with existing products (including a registered trademark in
the DDoS-mitigation space). If this grows beyond a personal/educational project,
do a USPTO/npm/pkg.go.dev/domain search and consider a rename.
