package dashboard

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// escapeLabel escapes a Prometheus label value per the exposition format:
// backslash, double-quote, and newline.
func escapeLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// ServePrometheus writes the current statistics in Prometheus text exposition
// format (version 0.0.4). It reuses the same counters the dashboard already
// collects from the event bus, so exposing metrics costs almost nothing.
func (s *Stats) ServePrometheus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	blocked := make(map[string]int64, len(s.BlockedByType))
	for k, v := range s.BlockedByType {
		blocked[k] = v
	}
	rps := s.RPS
	s.mu.RUnlock()

	total := atomic.LoadInt64(&s.TotalRequests)
	forwarded := atomic.LoadInt64(&s.TotalForwarded)
	totalBlocked := atomic.LoadInt64(&s.TotalBlocked)
	activeBans := s.countActiveBans()
	uptime := time.Since(s.startTime).Seconds()

	var b strings.Builder
	fmt.Fprintf(&b, "# HELP proxyshield_requests_total Total requests received.\n")
	fmt.Fprintf(&b, "# TYPE proxyshield_requests_total counter\n")
	fmt.Fprintf(&b, "proxyshield_requests_total %d\n", total)

	fmt.Fprintf(&b, "# HELP proxyshield_forwarded_total Requests forwarded to the backend.\n")
	fmt.Fprintf(&b, "# TYPE proxyshield_forwarded_total counter\n")
	fmt.Fprintf(&b, "proxyshield_forwarded_total %d\n", forwarded)

	fmt.Fprintf(&b, "# HELP proxyshield_blocked_total Requests blocked by a security layer.\n")
	fmt.Fprintf(&b, "# TYPE proxyshield_blocked_total counter\n")
	fmt.Fprintf(&b, "proxyshield_blocked_total %d\n", totalBlocked)

	fmt.Fprintf(&b, "# HELP proxyshield_blocked_by_type_total Blocked requests by threat type.\n")
	fmt.Fprintf(&b, "# TYPE proxyshield_blocked_by_type_total counter\n")
	for tag, n := range blocked {
		fmt.Fprintf(&b, "proxyshield_blocked_by_type_total{threat=\"%s\"} %d\n", escapeLabel(tag), n)
	}

	fmt.Fprintf(&b, "# HELP proxyshield_active_bans Currently active device bans.\n")
	fmt.Fprintf(&b, "# TYPE proxyshield_active_bans gauge\n")
	fmt.Fprintf(&b, "proxyshield_active_bans %d\n", activeBans)

	fmt.Fprintf(&b, "# HELP proxyshield_requests_per_second Recent requests-per-second (10s window).\n")
	fmt.Fprintf(&b, "# TYPE proxyshield_requests_per_second gauge\n")
	fmt.Fprintf(&b, "proxyshield_requests_per_second %g\n", rps)

	fmt.Fprintf(&b, "# HELP proxyshield_uptime_seconds Proxy uptime in seconds.\n")
	fmt.Fprintf(&b, "# TYPE proxyshield_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "proxyshield_uptime_seconds %g\n", uptime)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(b.String()))
}
