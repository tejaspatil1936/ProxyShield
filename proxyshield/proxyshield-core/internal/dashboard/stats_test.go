package dashboard

import (
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/middleware"
)

func TestStatsServeHTTPReturnsJSON(t *testing.T) {
	s := NewStats(event.NewBus(16), &sync.Map{})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/stats", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("stats response is not valid JSON: %v", err)
	}
	for _, k := range []string{"totalRequests", "totalBlocked", "blockedByType", "activeBans"} {
		if _, ok := out[k]; !ok {
			t.Errorf("stats JSON missing %q", k)
		}
	}
}

func TestStatsCountsOnlyActiveBans(t *testing.T) {
	banMap := &sync.Map{}
	banMap.Store("active", middleware.BanEntry{BannedAt: time.Now(), BanDuration: time.Hour})
	banMap.Store("expired", middleware.BanEntry{BannedAt: time.Now().Add(-2 * time.Hour), BanDuration: time.Hour})
	s := NewStats(event.NewBus(16), banMap)

	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/stats", nil))
	var out struct {
		ActiveBans int `json:"activeBans"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.ActiveBans != 1 {
		t.Errorf("expected exactly 1 active ban (expired excluded), got %d", out.ActiveBans)
	}
}

// Run with -race: /stats snapshots BlockedByType while Start() writes it.
func TestStatsServeHTTPConcurrentWithEvents(t *testing.T) {
	bus := event.NewBus(2000)
	s := NewStats(bus, &sync.Map{})
	go s.Start(bus)
	time.Sleep(5 * time.Millisecond) // let the collector subscribe

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			bus.Publish(event.Event{Name: event.RequestBlocked, Data: map[string]interface{}{"threatTag": "SQL_INJECTION"}})
		}
		close(done)
	}()

	for i := 0; i < 300; i++ {
		s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/stats", nil))
	}
	<-done
}
