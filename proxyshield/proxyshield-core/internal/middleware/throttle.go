package middleware

import (
	"net/http"
	"time"

	"github.com/tejaspatil1936/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/proxyshield-core/internal/reqctx"
)

// Throttle introduces graduated delays as request rates approach configured limits.
// It never blocks — it only slows requests down.
type Throttle struct {
	config *config.Config
}

// NewThrottle creates a Throttle middleware.
func NewThrottle(cfg *config.Config) *Throttle {
	return &Throttle{config: cfg}
}

// Name returns the middleware identifier.
func (m *Throttle) Name() string { return "throttle" }

// Handle applies a delay if the request is approaching its rate limit threshold.
// Always returns false — throttle never blocks a request.
func (m *Throttle) Handle(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool {
	if ctx.RateLimitInfo == nil {
		return false
	}
	if !ctx.RateLimitInfo.ThrottleEnabled {
		return false
	}

	ratio := float64(ctx.RateLimitInfo.Current) / float64(ctx.RateLimitInfo.Limit)

	// Defaults are applied once in config.Validate, so the config values are
	// already non-zero here — no need to re-derive them.
	t := m.config.Throttle

	var delayMs int
	if ratio >= t.CriticalThreshold {
		delayMs = t.CriticalDelayMs
	} else if ratio >= t.WarnThreshold {
		delayMs = t.WarnDelayMs
	}

	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
		ctx.EventBus.Publish(event.Event{
			Name: event.RateLimitWarning,
			Data: map[string]interface{}{
				"ip":           ctx.IP,
				"path":         r.URL.Path,
				"usagePercent": ratio * 100,
				"delayMs":      delayMs,
			},
			Timestamp: time.Now(),
		})
	}

	return false
}
