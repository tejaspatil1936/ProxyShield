package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/algorithm"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

// RateLimiter enforces per-IP per-endpoint rate limits using either the token
// bucket or sliding window algorithm based on config.
type RateLimiter struct {
	config        *config.Config
	tokenBucket   *algorithm.TokenBucket
	slidingWindow *algorithm.SlidingWindow
}

// NewRateLimiter creates a RateLimiter middleware.
func NewRateLimiter(cfg *config.Config, tb *algorithm.TokenBucket, sw *algorithm.SlidingWindow) *RateLimiter {
	return &RateLimiter{config: cfg, tokenBucket: tb, slidingWindow: sw}
}

// Name returns the middleware identifier.
func (m *RateLimiter) Name() string { return "rate-limiter" }

// Handle checks the request against configured rate limit rules.
func (m *RateLimiter) Handle(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool {
	// Find matching rule by path and method.
	var matched *config.RateLimitRule
	for i := range m.config.RateLimits {
		rule := &m.config.RateLimits[i]
		if rule.Path == r.URL.Path && strings.EqualFold(rule.Method, r.Method) {
			matched = rule
			break
		}
	}
	if matched == nil {
		return false
	}

	// Use device fingerprint when available so NAT peers get independent buckets.
	identifier := ctx.IP
	if ctx.Fingerprint != "" {
		identifier = ctx.Fingerprint
	}
	key := fmt.Sprintf("%s:%s:%s", identifier, r.Method, matched.Path)

	var result algorithm.RateLimitResult
	if matched.Algorithm == "token_bucket" {
		result = m.tokenBucket.Check(key, matched.Limit, matched.WindowSeconds)
	} else {
		result = m.slidingWindow.Check(key, matched.Limit, matched.WindowSeconds)
	}

	ctx.RateLimitInfo = &reqctx.RateLimitInfo{
		Limit:           result.Limit,
		Current:         result.Current,
		Remaining:       result.Remaining,
		ResetTime:       result.ResetTime,
		ThrottleEnabled: matched.ThrottleEnabled,
		Path:            matched.Path,
	}

	if !result.Allowed {
		threatTag := "RATE_LIMITED"
		if matched.Limit <= 10 || strings.Contains(matched.Path, "login") {
			threatTag = "BRUTE_FORCE"
		}

		retryAfter := result.ResetTime - time.Now().Unix()
		if retryAfter < 0 {
			retryAfter = 0
		}

		w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetTime, 10))
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":      "Rate limit exceeded",
			"retryAfter": retryAfter,
		})

		ctx.EventBus.Publish(event.Event{
			Name: event.RequestBlocked,
			Data: map[string]interface{}{
				"ip": ctx.IP, "path": r.URL.Path, "threatTag": threatTag,
				"fingerprint": ctx.Fingerprint,
			},
			Timestamp: time.Now(),
		})
		return true
	}

	return false
}
