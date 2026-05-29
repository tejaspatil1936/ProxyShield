package dashboard

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/middleware"
)

func TestServePrometheusExposesMetrics(t *testing.T) {
	banMap := &sync.Map{}
	banMap.Store("b", middleware.BanEntry{BannedAt: time.Now(), BanDuration: time.Hour})
	s := NewStats(event.NewBus(16), banMap)

	w := httptest.NewRecorder()
	s.ServePrometheus(w, httptest.NewRequest("GET", "/metrics", nil))

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", ct)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE proxyshield_requests_total counter",
		"proxyshield_requests_total ",
		"proxyshield_blocked_total ",
		"proxyshield_active_bans 1",
		"proxyshield_uptime_seconds ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}
