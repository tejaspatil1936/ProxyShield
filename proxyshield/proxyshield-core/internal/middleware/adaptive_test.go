package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

func adaptiveCtx() *reqctx.Context {
	return &reqctx.Context{IP: "1.2.3.4", EventBus: event.NewBus(64)}
}

func TestAdaptiveDisabledAlwaysAllows(t *testing.T) {
	cfg := &config.Config{}
	cfg.Adaptive.Enabled = false
	m := NewAdaptiveRateLimiter(cfg, NewAdaptiveTracker())
	for i := 0; i < 50; i++ {
		if m.Handle(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), adaptiveCtx()) {
			t.Fatal("a disabled adaptive limiter must allow every request")
		}
	}
}

func TestAdaptiveLearningPhaseAllows(t *testing.T) {
	cfg := &config.Config{}
	cfg.Adaptive.Enabled = true
	cfg.Adaptive.LearningRequests = 1000
	cfg.Adaptive.SpikeMultiplier = 3.0
	cfg.Adaptive.DecayPerBucket = 0.15
	m := NewAdaptiveRateLimiter(cfg, NewAdaptiveTracker())
	ctx := adaptiveCtx()
	for i := 0; i < 100; i++ {
		if m.Handle(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), ctx) {
			t.Fatal("requests within the learning window must not be blocked")
		}
	}
}

func TestAdaptiveRecordAccumulatesWithoutFalsePenalty(t *testing.T) {
	at := NewAdaptiveTracker()
	cfg := &config.AdaptiveConfig{Enabled: true, SpikeMultiplier: 3.0, LearningRequests: 20, DecayPerBucket: 0.15}
	for i := 0; i < 10; i++ {
		_, _, penalty, total := at.record("dev", cfg)
		if total != int64(i+1) {
			t.Fatalf("totalSeen should be %d, got %d", i+1, total)
		}
		// All requests land in the same 10s bucket → no historical baseline, so
		// steady traffic must not accrue a penalty.
		if penalty != 0 {
			t.Fatalf("steady single-bucket traffic must not be penalized, got %f", penalty)
		}
	}
}
