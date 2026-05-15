package middleware

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

// BanEntry records when a device was banned and for how long.
// Shared between IPBlacklist and Honeypot.
type BanEntry struct {
	BannedAt    time.Time
	BanDuration time.Duration
	IP          string // raw IP at time of ban (for logging / dashboard display)
	Fingerprint string // device fingerprint at time of ban (ban map key when non-empty)
}

// IPBlacklist is the first middleware in the chain. It checks both the static
// blacklist from config and the runtime ban map populated by the honeypot middleware.
type IPBlacklist struct {
	config    *config.Config
	banMap    *sync.Map
	blacklist map[string]bool
}

// NewIPBlacklist creates an IPBlacklist middleware, pre-building the O(1) lookup map.
func NewIPBlacklist(cfg *config.Config, banMap *sync.Map) *IPBlacklist {
	bl := make(map[string]bool, len(cfg.Security.BlacklistedIPs))
	for _, ip := range cfg.Security.BlacklistedIPs {
		bl[ip] = true
	}
	return &IPBlacklist{config: cfg, banMap: banMap, blacklist: bl}
}

// Name returns the middleware identifier.
func (m *IPBlacklist) Name() string { return "ip-blacklist" }

// Handle blocks requests from statically blacklisted or runtime-banned devices.
// Static blacklist is always checked by IP. Dynamic ban map is checked by device
// fingerprint first (if available), falling back to raw IP for backwards compatibility.
func (m *IPBlacklist) Handle(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool {
	// Static config blacklist — keyed by IP only.
	if m.blacklist[ctx.IP] {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":  "Forbidden",
			"reason": "BLACKLISTED_IP",
		})
		ctx.EventBus.Publish(event.Event{
			Name: event.RequestBlocked,
			Data: map[string]interface{}{
				"ip": ctx.IP, "path": r.URL.Path, "threatTag": "BLACKLISTED_IP",
				"fingerprint": ctx.Fingerprint,
			},
			Timestamp: time.Now(),
		})
		return true
	}

	// Dynamic ban map — prefer fingerprint key so NAT peers aren't cross-banned.
	banKey := ctx.IP
	if ctx.Fingerprint != "" {
		banKey = ctx.Fingerprint
	}

	if blocked, expired := m.checkBan(banKey, w, r, ctx); expired {
		m.banMap.Delete(banKey)
	} else if blocked {
		return true
	} else if ctx.Fingerprint != "" && banKey != ctx.IP {
		// Also check legacy IP-keyed entries for devices banned before fingerprinting.
		if blocked, expired := m.checkBan(ctx.IP, w, r, ctx); expired {
			m.banMap.Delete(ctx.IP)
		} else if blocked {
			return true
		}
	}

	return false
}

func (m *IPBlacklist) checkBan(key string, w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) (blocked, expired bool) {
	val, ok := m.banMap.Load(key)
	if !ok {
		return false, false
	}
	entry := val.(BanEntry)
	if time.Now().Before(entry.BannedAt.Add(entry.BanDuration)) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":  "Forbidden",
			"reason": "BANNED_DEVICE",
		})
		ctx.EventBus.Publish(event.Event{
			Name: event.RequestBlocked,
			Data: map[string]interface{}{
				"ip": ctx.IP, "path": r.URL.Path, "threatTag": "BANNED_DEVICE",
				"fingerprint": ctx.Fingerprint,
			},
			Timestamp: time.Now(),
		})
		return true, false
	}
	return false, true
}

// writeJSON writes a JSON response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	data, _ := json.Marshal(body)
	w.Write(data)
}
