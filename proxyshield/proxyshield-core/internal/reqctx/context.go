// Package reqctx defines the per-request context shared between proxy and middleware layers.
// It lives in a separate package to avoid import cycles between proxy and middleware.
package reqctx

import (
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
)

// RateLimitInfo carries rate limit metadata for a request, populated by the
// rate-limiter middleware and consumed by the throttle middleware and headers wrapper.
type RateLimitInfo struct {
	Limit           int
	Current         int
	Remaining       int
	ResetTime       int64
	ThrottleEnabled bool
	Path            string
}

// Context holds per-request state that flows through the middleware chain.
// A fresh Context is created for every incoming request.
type Context struct {
	IP                 string
	Body               []byte
	BodyText           string
	StartTime          time.Time
	RateLimitInfo      *RateLimitInfo
	Config             *config.Config
	EventBus           *event.Bus
	Fingerprint        string // SHA-256 based device fingerprint (first 16 hex chars)
	FingerprintDetails string // Human-readable: "Chrome/120 | en-US | gzip"
}
