package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

// Honeypot bans any IP that accesses a configured trap URL.
type Honeypot struct {
	config *config.Config
	banMap *sync.Map
}

// NewHoneypot creates a Honeypot middleware.
func NewHoneypot(cfg *config.Config, banMap *sync.Map) *Honeypot {
	return &Honeypot{config: cfg, banMap: banMap}
}

// Name returns the middleware identifier.
func (m *Honeypot) Name() string { return "honeypot" }

// Handle bans the client device if it accesses any configured honeypot path.
// The ban key is the device fingerprint when available, otherwise the raw IP.
// Both IP and fingerprint are stored in the BanEntry for dashboard display.
func (m *Honeypot) Handle(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool {
	path := r.URL.Path

	for _, hp := range m.config.Honeypots {
		// Case-insensitive so scanners probing /Admin, /.ENV, etc. don't evade
		// a lowercase trap definition.
		if !strings.EqualFold(path, hp.Path) {
			continue
		}

		banKey := ctx.IP
		if ctx.Fingerprint != "" {
			banKey = ctx.Fingerprint
		}

		banDuration := time.Duration(hp.BanMinutes) * time.Minute
		m.banMap.Store(banKey, BanEntry{
			BannedAt:    time.Now(),
			BanDuration: banDuration,
			IP:          ctx.IP,
			Fingerprint: ctx.Fingerprint,
		})

		ctx.EventBus.Publish(event.Event{
			Name: event.IPBanned,
			Data: map[string]interface{}{
				"ip": ctx.IP, "path": path, "banMinutes": hp.BanMinutes,
				"fingerprint": ctx.Fingerprint, "details": ctx.FingerprintDetails,
			},
			Timestamp: time.Now(),
		})
		ctx.EventBus.Publish(event.Event{
			Name: event.RequestBlocked,
			Data: map[string]interface{}{
				"ip": ctx.IP, "path": path, "threatTag": "HONEYPOT_TRAP",
				"fingerprint": ctx.Fingerprint, "details": ctx.FingerprintDetails,
			},
			Timestamp: time.Now(),
		})

		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":  "Forbidden",
			"reason": "HONEYPOT_TRAP",
		})
		return true
	}

	return false
}
