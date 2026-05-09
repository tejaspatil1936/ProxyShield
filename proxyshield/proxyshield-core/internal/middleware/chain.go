// Package middleware provides the security middleware pipeline for the proxy.
package middleware

import (
	"net/http"
	"sync"

	"github.com/tejaspatil1936/proxyshield-core/internal/algorithm"
	"github.com/tejaspatil1936/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/proxyshield-core/internal/reqctx"
)

// Middleware is the interface every security layer implements.
// Handle inspects the request and either blocks it (returns true) or passes it along (returns false).
type Middleware interface {
	// Name returns the middleware identifier for logging and config mapping.
	Name() string
	// Handle processes the request. Returns true if the request was blocked (response already written).
	// Returns false if the request should continue to the next middleware.
	Handle(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool
}

// RunChain executes each middleware in order.
// Returns true if any middleware blocked the request.
func RunChain(chain []Middleware, w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool {
	for _, mw := range chain {
		blocked := mw.Handle(w, r, ctx)
		if blocked {
			return true
		}
	}
	return false
}

// BuildChain creates the middleware chain from config.
// The banMap is shared between IPBlacklist and Honeypot.
// "headers" and "cache" are excluded — they are handled directly in proxy/server.go.
func BuildChain(cfg *config.Config, banMap *sync.Map, tb *algorithm.TokenBucket, sw *algorithm.SlidingWindow, at *AdaptiveTracker) []Middleware {
	factories := map[string]func() Middleware{
		"fingerprint":  func() Middleware { return NewDeviceFingerprinter() },
		"ip-blacklist": func() Middleware { return NewIPBlacklist(cfg, banMap) },
		"waf":          func() Middleware { return NewWAF(cfg) },
		"honeypot":     func() Middleware { return NewHoneypot(cfg, banMap) },
		"rate-limiter": func() Middleware { return NewRateLimiter(cfg, tb, sw) },
		"adaptive":     func() Middleware { return NewAdaptiveRateLimiter(cfg, at) },
		"throttle":     func() Middleware { return NewThrottle(cfg) },
		"headers":      nil, // handled via RateLimitResponseWriter wrapper
		"cache":        nil, // handled in proxy/server.go (needs recorder pattern)
	}

	var chain []Middleware
	for _, name := range cfg.Middlewares {
		if name == "headers" || name == "cache" {
			continue
		}
		if factory, ok := factories[name]; ok && factory != nil {
			chain = append(chain, factory())
		}
	}
	return chain
}
