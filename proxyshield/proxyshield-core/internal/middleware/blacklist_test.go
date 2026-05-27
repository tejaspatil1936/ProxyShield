package middleware

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

func blCtx(ip, fp string) *reqctx.Context {
	return &reqctx.Context{IP: ip, Fingerprint: fp, EventBus: event.NewBus(16)}
}

func TestBlacklistBlocksStaticIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.BlacklistedIPs = []string{"1.2.3.4"}
	bl := NewIPBlacklist(cfg, &sync.Map{})
	r := httptest.NewRequest("GET", "/", nil)
	if !bl.Handle(httptest.NewRecorder(), r, blCtx("1.2.3.4", "")) {
		t.Fatal("statically blacklisted IP should be blocked")
	}
}

func TestBlacklistAllowsCleanIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.BlacklistedIPs = []string{"1.2.3.4"}
	bl := NewIPBlacklist(cfg, &sync.Map{})
	r := httptest.NewRequest("GET", "/", nil)
	if bl.Handle(httptest.NewRecorder(), r, blCtx("9.9.9.9", "")) {
		t.Fatal("non-blacklisted IP should pass")
	}
}

func TestBlacklistBlocksActiveBanByFingerprint(t *testing.T) {
	banMap := &sync.Map{}
	banMap.Store("fp123", BanEntry{BannedAt: time.Now(), BanDuration: time.Hour, Fingerprint: "fp123"})
	bl := NewIPBlacklist(&config.Config{}, banMap)
	r := httptest.NewRequest("GET", "/", nil)
	if !bl.Handle(httptest.NewRecorder(), r, blCtx("1.2.3.4", "fp123")) {
		t.Fatal("device with an active ban should be blocked")
	}
}

func TestBlacklistExpiredBanIsRemoved(t *testing.T) {
	banMap := &sync.Map{}
	banMap.Store("fp123", BanEntry{BannedAt: time.Now().Add(-2 * time.Hour), BanDuration: time.Hour, Fingerprint: "fp123"})
	bl := NewIPBlacklist(&config.Config{}, banMap)
	r := httptest.NewRequest("GET", "/", nil)
	if bl.Handle(httptest.NewRecorder(), r, blCtx("1.2.3.4", "fp123")) {
		t.Fatal("an expired ban must not block")
	}
	if _, ok := banMap.Load("fp123"); ok {
		t.Fatal("an expired ban should be lazily deleted")
	}
}
