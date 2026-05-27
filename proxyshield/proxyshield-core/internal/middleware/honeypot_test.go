package middleware

import (
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

func honeypotCfg() *config.Config {
	return &config.Config{Honeypots: []config.HoneypotConfig{{Path: "/admin", BanMinutes: 5}}}
}

func hpCtx(fp string) *reqctx.Context {
	return &reqctx.Context{IP: "1.2.3.4", Fingerprint: fp, EventBus: event.NewBus(16)}
}

func TestHoneypotBansOnTrapPath(t *testing.T) {
	banMap := &sync.Map{}
	hp := NewHoneypot(honeypotCfg(), banMap)
	r := httptest.NewRequest("GET", "/admin", nil)
	if !hp.Handle(httptest.NewRecorder(), r, hpCtx("fp")) {
		t.Fatal("trap path should be blocked")
	}
	if _, ok := banMap.Load("fp"); !ok {
		t.Fatal("hitting a honeypot should record a ban keyed by fingerprint")
	}
}

func TestHoneypotIsCaseInsensitive(t *testing.T) {
	hp := NewHoneypot(honeypotCfg(), &sync.Map{})
	r := httptest.NewRequest("GET", "/Admin", nil)
	if !hp.Handle(httptest.NewRecorder(), r, hpCtx("fp")) {
		t.Fatal("/Admin should trigger the /admin trap (case-insensitive match)")
	}
}

func TestHoneypotIgnoresNonTrapPath(t *testing.T) {
	hp := NewHoneypot(honeypotCfg(), &sync.Map{})
	r := httptest.NewRequest("GET", "/api/keys", nil)
	if hp.Handle(httptest.NewRecorder(), r, hpCtx("fp")) {
		t.Fatal("a normal path must not trigger the honeypot")
	}
}
