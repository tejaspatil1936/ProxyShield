package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/algorithm"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

func newRateLimiter(rules ...config.RateLimitRule) *RateLimiter {
	return NewRateLimiter(&config.Config{RateLimits: rules}, algorithm.NewTokenBucket(), algorithm.NewSlidingWindow())
}

func rlCtx(fp string) *reqctx.Context {
	return &reqctx.Context{IP: "1.2.3.4", Fingerprint: fp, EventBus: event.NewBus(16)}
}

func TestRateLimiterBlocksOverLimit(t *testing.T) {
	rl := newRateLimiter(config.RateLimitRule{Path: "/login", Method: "POST", Limit: 2, WindowSeconds: 60, Algorithm: "sliding_window"})
	ctx := rlCtx("")
	r := httptest.NewRequest("POST", "/login", nil)
	for i := 0; i < 2; i++ {
		if rl.Handle(httptest.NewRecorder(), r, ctx) {
			t.Fatalf("request %d within limit should pass", i+1)
		}
	}
	if !rl.Handle(httptest.NewRecorder(), r, ctx) {
		t.Fatal("request over the limit should return 429")
	}
}

func TestRateLimiterIgnoresUnmatchedPath(t *testing.T) {
	rl := newRateLimiter(config.RateLimitRule{Path: "/login", Method: "POST", Limit: 1, WindowSeconds: 60})
	ctx := rlCtx("")
	if rl.Handle(httptest.NewRecorder(), httptest.NewRequest("GET", "/other", nil), ctx) {
		t.Fatal("a path with no matching rule must not be limited")
	}
	if ctx.RateLimitInfo != nil {
		t.Fatal("no matching rule should leave RateLimitInfo unset")
	}
}

func TestRateLimiterPopulatesInfo(t *testing.T) {
	rl := newRateLimiter(config.RateLimitRule{Path: "/x", Method: "GET", Limit: 5, WindowSeconds: 60, Algorithm: "token_bucket"})
	ctx := rlCtx("")
	rl.Handle(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil), ctx)
	if ctx.RateLimitInfo == nil || ctx.RateLimitInfo.Limit != 5 {
		t.Fatal("RateLimitInfo should be populated with the matched rule's limit")
	}
}

func TestRateLimiterFingerprintIsolation(t *testing.T) {
	rl := newRateLimiter(config.RateLimitRule{Path: "/x", Method: "GET", Limit: 1, WindowSeconds: 60, Algorithm: "sliding_window"})
	r := httptest.NewRequest("GET", "/x", nil)
	ctxA := rlCtx("A")
	ctxB := rlCtx("B") // same IP, different device fingerprint

	if rl.Handle(httptest.NewRecorder(), r, ctxA) {
		t.Fatal("device A's first request should pass")
	}
	if !rl.Handle(httptest.NewRecorder(), r, ctxA) {
		t.Fatal("device A's second request should be limited")
	}
	if rl.Handle(httptest.NewRecorder(), r, ctxB) {
		t.Fatal("device B shares the IP but must have an independent bucket")
	}
}
