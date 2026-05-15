package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

const (
	adaptiveBucketSec  = 10 // each bucket covers 10 seconds
	adaptiveHistoryLen = 30 // 30 buckets = 5 minutes of history
)

// DeviceProfile tracks the traffic pattern of a single device over a rolling
// 5-minute window of 10-second buckets.
type DeviceProfile struct {
	mu         sync.Mutex
	buckets    [adaptiveHistoryLen]int32 // request counts per bucket
	current    int                       // index into buckets
	lastBucket int64                     // unix-second of current bucket start
	totalSeen  int64                     // lifetime request count
	firstSeen  int64                     // unix-second
	penalty    float64                   // 0.0 = normal, 1.0 = max restriction
}

// AdaptiveTracker holds per-device traffic profiles. It is created once and
// lives for the lifetime of the proxy (same pattern as TokenBucket / SlidingWindow).
type AdaptiveTracker struct {
	profiles sync.Map // key (fingerprint or IP) → *DeviceProfile
}

// NewAdaptiveTracker creates a tracker and starts a background goroutine that
// evicts profiles that have been inactive for more than 10 minutes.
func NewAdaptiveTracker() *AdaptiveTracker {
	at := &AdaptiveTracker{}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Unix() - 600
			at.profiles.Range(func(k, v interface{}) bool {
				p := v.(*DeviceProfile)
				p.mu.Lock()
				stale := p.lastBucket < cutoff
				p.mu.Unlock()
				if stale {
					at.profiles.Delete(k)
				}
				return true
			})
		}
	}()
	return at
}

// record increments the device's current bucket, advances time, and computes
// the baseline rate, current rate, and penalty.
func (at *AdaptiveTracker) record(key string, cfg *config.AdaptiveConfig) (baseline, currentRate, penalty float64, totalSeen int64) {
	now := time.Now().Unix()
	bucketStart := now - (now % adaptiveBucketSec)

	val, _ := at.profiles.LoadOrStore(key, &DeviceProfile{
		firstSeen:  now,
		lastBucket: bucketStart,
	})
	p := val.(*DeviceProfile)

	p.mu.Lock()
	defer p.mu.Unlock()

	// Advance buckets for elapsed time, decaying penalty each step.
	if bucketStart > p.lastBucket {
		elapsed := int((bucketStart - p.lastBucket) / adaptiveBucketSec)
		if elapsed > adaptiveHistoryLen {
			elapsed = adaptiveHistoryLen
		}
		for i := 0; i < elapsed; i++ {
			p.current = (p.current + 1) % adaptiveHistoryLen
			p.buckets[p.current] = 0
			p.penalty -= cfg.DecayPerBucket
			if p.penalty < 0 {
				p.penalty = 0
			}
		}
		p.lastBucket = bucketStart
	}

	p.buckets[p.current]++
	p.totalSeen++

	// Baseline: average of non-zero historical buckets (excluding current).
	var sum int32
	var count int
	for i := 0; i < adaptiveHistoryLen; i++ {
		if i == p.current {
			continue
		}
		if p.buckets[i] > 0 {
			sum += p.buckets[i]
			count++
		}
	}
	if count > 0 {
		baseline = float64(sum) / float64(count)
	}

	currentRate = float64(p.buckets[p.current])

	// Spike detection: only enforce after the learning phase.
	if p.totalSeen >= cfg.LearningRequests && baseline > 0 {
		if currentRate > cfg.SpikeMultiplier*baseline {
			p.penalty += 0.3
			if p.penalty > 1.0 {
				p.penalty = 1.0
			}
		}
	}

	penalty = p.penalty
	totalSeen = p.totalSeen
	return
}

// AdaptiveRateLimiter blocks requests from devices exhibiting anomalous
// traffic spikes. It learns per-device baselines and auto-tightens when
// a device exceeds its learned norm.
type AdaptiveRateLimiter struct {
	tracker *AdaptiveTracker
	config  *config.Config
}

// NewAdaptiveRateLimiter creates an AdaptiveRateLimiter.
func NewAdaptiveRateLimiter(cfg *config.Config, tracker *AdaptiveTracker) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{tracker: tracker, config: cfg}
}

// Name returns the middleware identifier.
func (m *AdaptiveRateLimiter) Name() string { return "adaptive" }

// Handle profiles the device's traffic and blocks if penalty exceeds threshold.
func (m *AdaptiveRateLimiter) Handle(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool {
	if !m.config.Adaptive.Enabled {
		return false
	}

	key := ctx.IP
	if ctx.Fingerprint != "" {
		key = ctx.Fingerprint
	}

	baseline, currentRate, penalty, totalSeen := m.tracker.record(key, &m.config.Adaptive)

	// Still in learning phase — allow everything.
	if totalSeen < m.config.Adaptive.LearningRequests {
		return false
	}

	// Block when penalty is severe.
	if penalty >= 0.5 {
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":    "Adaptive rate limit exceeded",
			"reason":   "ANOMALOUS_TRAFFIC",
			"baseline": baseline,
			"current":  currentRate,
			"penalty":  penalty,
		})
		ctx.EventBus.Publish(event.Event{
			Name: event.RequestBlocked,
			Data: map[string]interface{}{
				"ip": ctx.IP, "path": r.URL.Path,
				"threatTag":   "ADAPTIVE_RATE_LIMIT",
				"fingerprint": ctx.Fingerprint,
				"baseline":    baseline,
				"currentRate": currentRate,
				"penalty":     penalty,
			},
			Timestamp: time.Now(),
		})
		return true
	}

	// Emit a warning when a spike is brewing but not yet blocking.
	if penalty > 0 {
		ctx.EventBus.Publish(event.Event{
			Name: event.RateLimitWarning,
			Data: map[string]interface{}{
				"ip": ctx.IP, "fingerprint": ctx.Fingerprint,
				"adaptive": true, "baseline": baseline,
				"currentRate": currentRate, "penalty": penalty,
			},
			Timestamp: time.Now(),
		})
	}

	return false
}
