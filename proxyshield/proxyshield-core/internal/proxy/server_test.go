package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
)

func cfgWithTrusted(cidrs ...string) *config.Config {
	c := &config.Config{}
	c.Server.ListenPort = 9090
	c.Server.BackendURL = "http://backend:1"
	c.Server.DashboardPort = 9091
	c.Server.TrustedProxies = cidrs
	_ = config.Validate(c) // populates the parsed trusted nets
	return c
}

func mkReq(remoteAddr, xff string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestExtractIPNoTrustedProxiesIgnoresXFF(t *testing.T) {
	cfg := cfgWithTrusted()
	if got := extractIP(mkReq("203.0.113.9:5555", "1.1.1.1"), cfg); got != "203.0.113.9" {
		t.Errorf("with no trusted proxies, XFF must be ignored: got %q want 203.0.113.9", got)
	}
}

func TestExtractIPUntrustedPeerIgnoresSpoofedXFF(t *testing.T) {
	cfg := cfgWithTrusted("10.0.0.0/8")
	if got := extractIP(mkReq("203.0.113.9:5555", "9.9.9.9"), cfg); got != "203.0.113.9" {
		t.Errorf("untrusted peer's XFF must be ignored: got %q want 203.0.113.9", got)
	}
}

func TestExtractIPTrustedPeerUsesXFF(t *testing.T) {
	cfg := cfgWithTrusted("10.0.0.0/8")
	if got := extractIP(mkReq("10.0.0.2:5555", "9.9.9.9"), cfg); got != "9.9.9.9" {
		t.Errorf("trusted peer's XFF client should be used: got %q want 9.9.9.9", got)
	}
}

func TestExtractIPWalksPastTrustedHops(t *testing.T) {
	cfg := cfgWithTrusted("10.0.0.0/8")
	// client 8.8.8.8 → trusted 10.0.0.5 → trusted peer 10.0.0.2
	if got := extractIP(mkReq("10.0.0.2:5555", "8.8.8.8, 10.0.0.5"), cfg); got != "8.8.8.8" {
		t.Errorf("should return the right-most untrusted address: got %q want 8.8.8.8", got)
	}
}

func TestExtractIPStripsPortFromRemoteAddr(t *testing.T) {
	cfg := cfgWithTrusted()
	if got := extractIP(mkReq("198.51.100.7:41234", ""), cfg); got != "198.51.100.7" {
		t.Errorf("expected host without port, got %q", got)
	}
}
