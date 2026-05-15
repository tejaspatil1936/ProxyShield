package middleware

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/algorithm"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

// WAF is the Web Application Firewall middleware. It detects SQL injection, XSS,
// and high-entropy anomalies. Regex patterns are compiled once at startup.
type WAF struct {
	config     *config.Config
	sqlPattern *regexp.Regexp
	xssPattern *regexp.Regexp
}

// NewWAF creates a WAF middleware, compiling regex patterns at construction time.
func NewWAF(cfg *config.Config) *WAF {
	sqlPattern := regexp.MustCompile(`(?i)(\b(union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+(table|database|column)|alter\s+table|create\s+(table|database)|exec(\s+|\()|execute(\s+|\()|xp_|sp_)\b|(--)|(/\*[\s\S]*?\*/)|\b(or|and)\s+\d+\s*=\s*\d+|('\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+)|(;\s*(drop|delete|update|insert|alter|create)))`)
	xssPattern := regexp.MustCompile(`(?i)(<\s*script|<\s*iframe|<\s*embed|<\s*object|javascript\s*:|on(error|load|click|mouseover|focus|blur|submit|change|input|keydown|keyup|keypress)\s*=|eval\s*\(|document\s*\.\s*(cookie|write|location)|window\s*\.\s*(location|open)|alert\s*\(|prompt\s*\(|confirm\s*\()`)

	return &WAF{
		config:     cfg,
		sqlPattern: sqlPattern,
		xssPattern: xssPattern,
	}
}

// Name returns the middleware identifier.
func (m *WAF) Name() string { return "waf" }

// Handle scans the request for SQL injection, XSS, and high-entropy payloads.
func (m *WAF) Handle(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool {
	// Collect all strings to scan
	targets := []string{r.URL.Path}
	for _, vals := range r.URL.Query() {
		targets = append(targets, vals...)
	}
	if ctx.BodyText != "" {
		targets = append(targets, ctx.BodyText)
	}

	if m.config.Security.BlockSQLInjection {
		for _, s := range targets {
			if m.sqlPattern.MatchString(s) {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":  "Forbidden",
					"reason": "SQL_INJECTION",
				})
				ctx.EventBus.Publish(event.Event{
					Name: event.RequestBlocked,
					Data: map[string]interface{}{
						"ip": ctx.IP, "path": r.URL.Path, "threatTag": "SQL_INJECTION",
					},
					Timestamp: time.Now(),
				})
				return true
			}
		}
	}

	if m.config.Security.BlockXSS {
		for _, s := range targets {
			if m.xssPattern.MatchString(s) {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":  "Forbidden",
					"reason": "XSS",
				})
				ctx.EventBus.Publish(event.Event{
					Name: event.RequestBlocked,
					Data: map[string]interface{}{
						"ip": ctx.IP, "path": r.URL.Path, "threatTag": "XSS",
					},
					Timestamp: time.Now(),
				})
				return true
			}
		}
	}

	// Entropy check on body
	if len(ctx.Body) > 0 {
		ct := r.Header.Get("Content-Type")
		if !shouldSkipEntropy(ct) {
			entropy := algorithm.CalculateEntropy(ctx.Body)
			if entropy > m.config.Security.EntropyThreshold {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":  "Forbidden",
					"reason": "HIGH_ENTROPY",
				})
				ctx.EventBus.Publish(event.Event{
					Name: event.RequestBlocked,
					Data: map[string]interface{}{
						"ip": ctx.IP, "path": r.URL.Path, "threatTag": "HIGH_ENTROPY",
					},
					Timestamp: time.Now(),
				})
				return true
			}
		}
	}

	return false
}

// shouldSkipEntropy returns true for content types where high entropy is expected.
func shouldSkipEntropy(ct string) bool {
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "multipart/form-data") ||
		strings.HasPrefix(ct, "application/octet-stream") ||
		strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/")
}
