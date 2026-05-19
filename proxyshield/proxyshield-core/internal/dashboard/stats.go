package dashboard

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/middleware"
)

// Stats collects and serves real-time proxy statistics.
type Stats struct {
	mu             sync.RWMutex
	TotalRequests  int64            `json:"totalRequests"`
	TotalForwarded int64            `json:"totalForwarded"`
	TotalBlocked   int64            `json:"totalBlocked"`
	BlockedByType  map[string]int64 `json:"blockedByType"`
	RPS            float64          `json:"requestsPerSecond"`
	ActiveBans     int              `json:"activeBans"`
	Uptime         float64          `json:"uptimeSeconds"`
	startTime      time.Time
	recentRequests []time.Time
	banMap         *sync.Map
}

// NewStats creates a Stats collector that subscribes to the event bus.
func NewStats(bus *event.Bus, banMap *sync.Map) *Stats {
	s := &Stats{
		BlockedByType: make(map[string]int64),
		startTime:     time.Now(),
		banMap:        banMap,
	}
	return s
}

// Start subscribes to events and updates statistics in the background.
// Run this in a goroutine.
func (s *Stats) Start(bus *event.Bus) {
	received := bus.Subscribe(event.RequestReceived)
	forwarded := bus.Subscribe(event.RequestForwarded)
	blocked := bus.Subscribe(event.RequestBlocked)

	rpsTicker := time.NewTicker(time.Second)
	defer rpsTicker.Stop()

	for {
		select {
		case <-received:
			atomic.AddInt64(&s.TotalRequests, 1)
			s.mu.Lock()
			s.recentRequests = append(s.recentRequests, time.Now())
			s.mu.Unlock()

		case <-forwarded:
			atomic.AddInt64(&s.TotalForwarded, 1)

		case evt := <-blocked:
			atomic.AddInt64(&s.TotalBlocked, 1)
			tag, _ := evt.Data["threatTag"].(string)
			if tag != "" {
				s.mu.Lock()
				s.BlockedByType[tag]++
				s.mu.Unlock()
			}

		case <-rpsTicker.C:
			s.updateRPS()
		}
	}
}

// updateRPS recalculates requests per second using a 10-second window.
func (s *Stats) updateRPS() {
	cutoff := time.Now().Add(-10 * time.Second)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Trim old timestamps
	start := 0
	for start < len(s.recentRequests) && s.recentRequests[start].Before(cutoff) {
		start++
	}
	s.recentRequests = s.recentRequests[start:]
	s.RPS = float64(len(s.recentRequests)) / 10.0
}

// countActiveBans counts non-expired entries in the ban map. The map is a
// *sync.Map of middleware.BanEntry keyed by device fingerprint (or IP); an
// entry is active only while now < BannedAt+BanDuration.
func (s *Stats) countActiveBans() int {
	if s.banMap == nil {
		return 0
	}
	count := 0
	now := time.Now()
	s.banMap.Range(func(_, v interface{}) bool {
		if entry, ok := v.(middleware.BanEntry); ok {
			if now.Before(entry.BannedAt.Add(entry.BanDuration)) {
				count++
			}
		}
		return true
	})
	return count
}

// ServeHTTP responds with the current statistics as JSON.
func (s *Stats) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	snapshot := struct {
		TotalRequests  int64            `json:"totalRequests"`
		TotalForwarded int64            `json:"totalForwarded"`
		TotalBlocked   int64            `json:"totalBlocked"`
		BlockedByType  map[string]int64 `json:"blockedByType"`
		RPS            float64          `json:"requestsPerSecond"`
		ActiveBans     int              `json:"activeBans"`
		Uptime         float64          `json:"uptimeSeconds"`
	}{
		TotalRequests:  atomic.LoadInt64(&s.TotalRequests),
		TotalForwarded: atomic.LoadInt64(&s.TotalForwarded),
		TotalBlocked:   atomic.LoadInt64(&s.TotalBlocked),
		BlockedByType:  s.BlockedByType,
		RPS:            s.RPS,
		ActiveBans:     s.countActiveBans(),
		Uptime:         time.Since(s.startTime).Seconds(),
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}
