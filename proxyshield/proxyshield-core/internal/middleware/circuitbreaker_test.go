package middleware

import (
	"testing"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
)

func cbCfg(failureThreshold, cooldown, successThreshold int) *config.CircuitBreakerConfig {
	return &config.CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: failureThreshold,
		CooldownSeconds:  cooldown,
		SuccessThreshold: successThreshold,
	}
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker()
	cfg := cbCfg(3, 30, 2)
	if !cb.Allow(cfg) {
		t.Fatal("breaker should start CLOSED and allow")
	}
	for i := 0; i < 3; i++ {
		cb.RecordFailure(cfg, nil)
	}
	if cb.State() != "OPEN" {
		t.Fatalf("expected OPEN after 3 failures, got %s", cb.State())
	}
	if cb.Allow(cfg) {
		t.Fatal("OPEN circuit within cooldown must reject")
	}
}

func TestCircuitBreakerHalfOpenAdmitsBoundedProbes(t *testing.T) {
	cb := NewCircuitBreaker()
	cfg := cbCfg(1, 0, 2) // cooldown 0 → immediate HALF_OPEN; allow up to 2 probes
	cb.RecordFailure(cfg, nil)
	if cb.State() != "OPEN" {
		t.Fatalf("expected OPEN, got %s", cb.State())
	}
	if !cb.Allow(cfg) {
		t.Fatal("first HALF_OPEN probe should be admitted")
	}
	if !cb.Allow(cfg) {
		t.Fatal("second HALF_OPEN probe should be admitted (SuccessThreshold=2)")
	}
	if cb.Allow(cfg) {
		t.Fatal("third probe exceeds SuccessThreshold and must be rejected (no thundering herd)")
	}
}

func TestCircuitBreakerClosesAfterSuccesses(t *testing.T) {
	cb := NewCircuitBreaker()
	cfg := cbCfg(1, 0, 2)
	cb.RecordFailure(cfg, nil) // OPEN
	cb.Allow(cfg)              // → HALF_OPEN
	cb.RecordSuccess(cfg, nil)
	cb.RecordSuccess(cfg, nil) // 2 successes → CLOSED
	if cb.State() != "CLOSED" {
		t.Fatalf("expected CLOSED after enough successes, got %s", cb.State())
	}
	if !cb.Allow(cfg) {
		t.Fatal("CLOSED circuit should allow")
	}
}

func TestCircuitBreakerReopensOnHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker()
	cfg := cbCfg(1, 0, 2)
	cb.RecordFailure(cfg, nil) // OPEN
	cb.Allow(cfg)              // → HALF_OPEN
	cb.RecordFailure(cfg, nil) // probe failed → OPEN
	if cb.State() != "OPEN" {
		t.Fatalf("expected OPEN after a HALF_OPEN probe failure, got %s", cb.State())
	}
}

func TestCircuitBreakerDisabledAlwaysAllows(t *testing.T) {
	cb := NewCircuitBreaker()
	cfg := &config.CircuitBreakerConfig{Enabled: false, FailureThreshold: 1}
	cb.RecordFailure(cfg, nil)
	if !cb.Allow(cfg) {
		t.Fatal("a disabled breaker must always allow")
	}
}
