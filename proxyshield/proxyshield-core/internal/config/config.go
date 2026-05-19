// Package config provides configuration loading, validation, and thread-safe access.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// Config is the top-level proxy configuration.
type Config struct {
	Server         ServerConfig         `json:"server"`
	Middlewares    []string             `json:"middlewares"`
	RateLimits     []RateLimitRule      `json:"rate_limits"`
	Security       SecurityConfig       `json:"security"`
	Honeypots      []HoneypotConfig     `json:"honeypots"`
	HoneypotFile   string               `json:"honeypot_file"` // optional path to external honeypots JSON
	Throttle       ThrottleConfig       `json:"throttle"`
	Dashboard      DashboardConfig      `json:"dashboard"`
	CircuitBreaker CircuitBreakerConfig `json:"circuit_breaker"`
	Cache          CacheConfig          `json:"cache"`
	Adaptive       AdaptiveConfig       `json:"adaptive"`

	// trustedNets is the parsed form of Server.TrustedProxies, populated by
	// Validate. It is not serialized.
	trustedNets []*net.IPNet
}

// AdaptiveConfig controls the per-device adaptive rate limiter.
type AdaptiveConfig struct {
	Enabled          bool    `json:"enabled"`
	SpikeMultiplier  float64 `json:"spike_multiplier"`  // e.g. 3.0 = block at 3× baseline
	LearningRequests int64   `json:"learning_requests"` // requests before enforcing
	DecayPerBucket   float64 `json:"decay_per_bucket"`  // penalty decay per 10s bucket
}

// CircuitBreakerConfig controls the circuit breaker that protects against backend failures.
type CircuitBreakerConfig struct {
	Enabled          bool `json:"enabled"`
	FailureThreshold int  `json:"failure_threshold"` // failures before opening
	CooldownSeconds  int  `json:"cooldown_seconds"`  // time in OPEN before trying HALF_OPEN
	SuccessThreshold int  `json:"success_threshold"` // successes in HALF_OPEN to close
}

// CacheRule defines a path+method combination to cache with a given TTL.
type CacheRule struct {
	Path       string `json:"path"`
	Method     string `json:"method"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// CacheConfig controls response caching for GET endpoints.
type CacheConfig struct {
	Enabled bool        `json:"enabled"`
	Rules   []CacheRule `json:"rules"`
}

// ServerConfig holds the proxy and dashboard listen ports and backend URL.
type ServerConfig struct {
	ListenPort    int    `json:"listen_port"`
	BackendURL    string `json:"backend_url"`
	DashboardPort int    `json:"dashboard_port"`

	// TrustedProxies lists CIDRs (or bare IPs) of upstream proxies/load balancers
	// whose X-Forwarded-For header may be trusted. If empty, X-Forwarded-For is
	// IGNORED and the direct peer (RemoteAddr) is used — the fail-closed default
	// that prevents header-spoofing attackers from forging a fresh identity per
	// request. Set this to your load balancer / platform edge CIDRs in production.
	TrustedProxies []string `json:"trusted_proxies"`

	// TLS optionally terminates HTTPS on the proxy listener.
	TLS TLSConfig `json:"tls"`
}

// TLSConfig configures optional HTTPS termination on the proxy listener.
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// RateLimitRule defines rate limiting behavior for a specific path and method.
type RateLimitRule struct {
	Path            string `json:"path"`
	Method          string `json:"method"`
	Limit           int    `json:"limit"`
	WindowSeconds   int    `json:"window_seconds"`
	Algorithm       string `json:"algorithm"`
	ThrottleEnabled bool   `json:"throttle_enabled"`
}

// SecurityConfig holds WAF, entropy, body size, and IP blacklist settings.
type SecurityConfig struct {
	BlockSQLInjection bool     `json:"block_sql_injection"`
	BlockXSS          bool     `json:"block_xss"`
	EntropyThreshold  float64  `json:"entropy_threshold"`
	MaxBodyBytes      int64    `json:"max_body_bytes"`
	BlacklistedIPs    []string `json:"blacklisted_ips"`
}

// HoneypotConfig defines a trap URL that triggers automatic IP bans.
type HoneypotConfig struct {
	Path       string `json:"path"`
	BanMinutes int    `json:"ban_minutes"`
}

// ThrottleConfig defines graduated delay thresholds and durations.
type ThrottleConfig struct {
	WarnThreshold     float64 `json:"warn_threshold"`
	WarnDelayMs       int     `json:"warn_delay_ms"`
	CriticalThreshold float64 `json:"critical_threshold"`
	CriticalDelayMs   int     `json:"critical_delay_ms"`
}

// DashboardConfig controls the real-time dashboard server.
type DashboardConfig struct {
	Enabled   bool `json:"enabled"`
	MaxEvents int  `json:"max_events"`
}

// Load reads and parses the config file at path, then validates it.
// If honeypot_file is set, honeypots are loaded from that file and merged
// with any inline honeypots defined in the config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Resolve honeypot_file relative to the config file's directory.
	if cfg.HoneypotFile != "" {
		hpPath := cfg.HoneypotFile
		if !strings.HasPrefix(hpPath, "/") {
			dir := "."
			if idx := strings.LastIndex(path, "/"); idx >= 0 {
				dir = path[:idx]
			}
			hpPath = dir + "/" + hpPath
		}
		extra, err := LoadHoneypotFile(hpPath)
		if err != nil {
			return nil, fmt.Errorf("loading honeypot_file %q: %w", hpPath, err)
		}
		// Merge: file entries first, then inline (inline overrides duplicates).
		merged := make([]HoneypotConfig, 0, len(extra)+len(cfg.Honeypots))
		seen := make(map[string]bool)
		for _, h := range cfg.Honeypots {
			seen[h.Path] = true
			merged = append(merged, h)
		}
		for _, h := range extra {
			if !seen[h.Path] {
				merged = append(merged, h)
			}
		}
		cfg.Honeypots = merged
	}

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// LoadHoneypotFile reads a JSON file containing an array of HoneypotConfig entries.
// Each entry must have a path and ban_minutes. Entries with a missing ban_minutes
// default to 30.
func LoadHoneypotFile(path string) ([]HoneypotConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Support two formats:
	//   1. Array of objects: [{"path":"/admin","ban_minutes":30}, ...]
	//   2. Array of strings: ["/admin", "/.env", ...] — uses default ban_minutes=30
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Try object format first.
	var entries []HoneypotConfig
	if err := json.Unmarshal(raw, &entries); err == nil {
		for i := range entries {
			if entries[i].BanMinutes <= 0 {
				entries[i].BanMinutes = 30
			}
		}
		return entries, nil
	}

	// Fall back to string array format.
	var paths []string
	if err := json.Unmarshal(raw, &paths); err != nil {
		return nil, fmt.Errorf("honeypot file must be a JSON array of objects or strings")
	}
	entries = make([]HoneypotConfig, 0, len(paths))
	for _, p := range paths {
		if p != "" {
			entries = append(entries, HoneypotConfig{Path: p, BanMinutes: 30})
		}
	}
	return entries, nil
}

// Validate checks all required fields and applies defaults for optional ones.
func Validate(cfg *Config) error {
	if cfg.Server.ListenPort < 1 || cfg.Server.ListenPort > 65535 {
		return fmt.Errorf("server.listen_port must be 1-65535")
	}
	if cfg.Server.BackendURL == "" {
		return fmt.Errorf("server.backend_url is required")
	}
	if !strings.HasPrefix(cfg.Server.BackendURL, "http://") && !strings.HasPrefix(cfg.Server.BackendURL, "https://") {
		return fmt.Errorf("server.backend_url must start with http:// or https://")
	}
	if cfg.Server.DashboardPort < 1 || cfg.Server.DashboardPort > 65535 {
		return fmt.Errorf("server.dashboard_port must be 1-65535")
	}
	if cfg.Server.DashboardPort == cfg.Server.ListenPort {
		return fmt.Errorf("server.dashboard_port must differ from server.listen_port")
	}

	// Parse trusted proxy CIDRs (or bare IPs) once, up front.
	cfg.trustedNets = cfg.trustedNets[:0]
	for i, entry := range cfg.Server.TrustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			// Bare IP → /32 or /128.
			if ip := net.ParseIP(entry); ip != nil {
				if ip.To4() != nil {
					entry += "/32"
				} else {
					entry += "/128"
				}
			}
		}
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("server.trusted_proxies[%d] %q: %w", i, cfg.Server.TrustedProxies[i], err)
		}
		cfg.trustedNets = append(cfg.trustedNets, ipNet)
	}

	if cfg.Server.TLS.Enabled {
		if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
			return fmt.Errorf("server.tls.cert_file and server.tls.key_file are required when tls.enabled")
		}
	}

	for i := range cfg.RateLimits {
		r := &cfg.RateLimits[i]
		if !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("rate_limits[%d].path must start with /", i)
		}
		method := strings.ToUpper(r.Method)
		switch method {
		case "GET", "POST", "PUT", "DELETE", "PATCH":
			r.Method = method
		default:
			return fmt.Errorf("rate_limits[%d].method must be GET/POST/PUT/DELETE/PATCH", i)
		}
		if r.Limit <= 0 {
			return fmt.Errorf("rate_limits[%d].limit must be > 0", i)
		}
		if r.WindowSeconds <= 0 {
			return fmt.Errorf("rate_limits[%d].window_seconds must be > 0", i)
		}
		if r.Algorithm == "" {
			r.Algorithm = "sliding_window"
		}
	}

	if cfg.Security.EntropyThreshold == 0 {
		cfg.Security.EntropyThreshold = 5.5
	}
	if cfg.Security.MaxBodyBytes == 0 {
		cfg.Security.MaxBodyBytes = 1048576
	}

	for i, h := range cfg.Honeypots {
		if !strings.HasPrefix(h.Path, "/") {
			return fmt.Errorf("honeypots[%d].path must start with /", i)
		}
		if h.BanMinutes <= 0 {
			return fmt.Errorf("honeypots[%d].ban_minutes must be > 0", i)
		}
	}

	if cfg.Throttle.WarnThreshold == 0 {
		cfg.Throttle.WarnThreshold = 0.8
	}
	if cfg.Throttle.WarnDelayMs == 0 {
		cfg.Throttle.WarnDelayMs = 200
	}
	if cfg.Throttle.CriticalThreshold == 0 {
		cfg.Throttle.CriticalThreshold = 0.9
	}
	if cfg.Throttle.CriticalDelayMs == 0 {
		cfg.Throttle.CriticalDelayMs = 500
	}

	if cfg.CircuitBreaker.FailureThreshold <= 0 {
		cfg.CircuitBreaker.FailureThreshold = 5
	}
	if cfg.CircuitBreaker.CooldownSeconds <= 0 {
		cfg.CircuitBreaker.CooldownSeconds = 30
	}
	if cfg.CircuitBreaker.SuccessThreshold <= 0 {
		cfg.CircuitBreaker.SuccessThreshold = 2
	}

	if cfg.Adaptive.SpikeMultiplier <= 0 {
		cfg.Adaptive.SpikeMultiplier = 3.0
	}
	if cfg.Adaptive.LearningRequests <= 0 {
		cfg.Adaptive.LearningRequests = 20
	}
	if cfg.Adaptive.DecayPerBucket <= 0 {
		cfg.Adaptive.DecayPerBucket = 0.15
	}

	return nil
}

// IsTrustedProxy reports whether ip falls within any configured trusted-proxy
// CIDR. With no trusted proxies configured it always returns false, so callers
// fall back to the direct peer address.
func (c *Config) IsTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range c.trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Holder provides thread-safe access to the current configuration.
type Holder struct {
	config *Config
	mu     sync.RWMutex
}

// NewHolder creates a new empty Holder.
func NewHolder() *Holder {
	return &Holder{}
}

// Get returns the current configuration under a read lock.
func (h *Holder) Get() *Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.config
}

// Set replaces the current configuration under a write lock.
func (h *Holder) Set(cfg *Config) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config = cfg
}
