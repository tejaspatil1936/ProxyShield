package config_test

import (
	"net"
	"testing"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
)

func baseConfig() *config.Config {
	c := &config.Config{}
	c.Server.ListenPort = 9090
	c.Server.BackendURL = "http://localhost:8080"
	c.Server.DashboardPort = 9091
	return c
}

func TestValidateAppliesDefaults(t *testing.T) {
	c := baseConfig()
	if err := config.Validate(c); err != nil {
		t.Fatalf("valid config should pass: %v", err)
	}
	if c.Security.EntropyThreshold != 5.5 {
		t.Errorf("expected default entropy 5.5, got %v", c.Security.EntropyThreshold)
	}
	if c.CircuitBreaker.FailureThreshold != 5 {
		t.Errorf("expected default failure threshold 5, got %d", c.CircuitBreaker.FailureThreshold)
	}
	if c.Adaptive.SpikeMultiplier != 3.0 {
		t.Errorf("expected default spike multiplier 3.0, got %v", c.Adaptive.SpikeMultiplier)
	}
	if c.Throttle.WarnThreshold != 0.8 {
		t.Errorf("expected default warn threshold 0.8, got %v", c.Throttle.WarnThreshold)
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	cases := map[string]func(*config.Config){
		"port 0":         func(c *config.Config) { c.Server.ListenPort = 0 },
		"missing backend": func(c *config.Config) { c.Server.BackendURL = "" },
		"non-http backend": func(c *config.Config) { c.Server.BackendURL = "ftp://x" },
		"same ports":      func(c *config.Config) { c.Server.DashboardPort = c.Server.ListenPort },
	}
	for name, mutate := range cases {
		c := baseConfig()
		mutate(c)
		if err := config.Validate(c); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestTrustedProxyParsing(t *testing.T) {
	c := baseConfig()
	c.Server.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.5"}
	if err := config.Validate(c); err != nil {
		t.Fatalf("valid trusted_proxies should pass: %v", err)
	}
	if !c.IsTrustedProxy(net.ParseIP("10.1.2.3")) {
		t.Error("10.1.2.3 should match the 10.0.0.0/8 CIDR")
	}
	if !c.IsTrustedProxy(net.ParseIP("192.168.1.5")) {
		t.Error("a bare trusted IP should match exactly")
	}
	if c.IsTrustedProxy(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 must not be trusted")
	}
}

func TestTrustedProxyInvalidCIDRRejected(t *testing.T) {
	c := baseConfig()
	c.Server.TrustedProxies = []string{"not-a-cidr"}
	if err := config.Validate(c); err == nil {
		t.Fatal("an invalid trusted proxy entry should error")
	}
}

func TestEmptyTrustedProxiesTrustsNothing(t *testing.T) {
	c := baseConfig()
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	if c.IsTrustedProxy(net.ParseIP("10.0.0.1")) {
		t.Error("with no trusted proxies configured, nothing should be trusted")
	}
}

func TestTLSRequiresCertAndKey(t *testing.T) {
	c := baseConfig()
	c.Server.TLS.Enabled = true
	if err := config.Validate(c); err == nil {
		t.Fatal("TLS enabled without cert/key should error")
	}
	c.Server.TLS.CertFile = "cert.pem"
	c.Server.TLS.KeyFile = "key.pem"
	if err := config.Validate(c); err != nil {
		t.Fatalf("TLS with cert and key should validate: %v", err)
	}
}
