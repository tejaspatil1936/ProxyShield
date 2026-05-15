package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

// DeviceFingerprinter computes a SHA-256 device fingerprint from IP + request headers.
// It runs first in the chain so that all downstream middlewares can use ctx.Fingerprint
// instead of ctx.IP for per-device tracking. This solves the NAT/WiFi problem where
// multiple devices share one public IP.
type DeviceFingerprinter struct{}

// NewDeviceFingerprinter creates a DeviceFingerprinter.
func NewDeviceFingerprinter() *DeviceFingerprinter { return &DeviceFingerprinter{} }

// Name returns the middleware identifier.
func (d *DeviceFingerprinter) Name() string { return "fingerprint" }

// Handle computes the device fingerprint and stores it on the request context.
// Never blocks — always returns false.
func (d *DeviceFingerprinter) Handle(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool {
	ua := r.Header.Get("User-Agent")
	lang := r.Header.Get("Accept-Language")
	enc := r.Header.Get("Accept-Encoding")

	raw := ctx.IP + "|" + ua + "|" + lang + "|" + enc
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	ctx.Fingerprint = hash[:16]

	browser := extractBrowserName(ua)
	ctx.FingerprintDetails = browser + " | " + lang + " | " + enc

	return false
}

// extractBrowserName returns a short browser label from a User-Agent string.
func extractBrowserName(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "edg/") || strings.Contains(lower, "edge/"):
		return "Edge"
	case strings.Contains(lower, "chrome/") && !strings.Contains(lower, "chromium"):
		return "Chrome"
	case strings.Contains(lower, "firefox/"):
		return "Firefox"
	case strings.Contains(lower, "safari/") && !strings.Contains(lower, "chrome"):
		return "Safari"
	case strings.Contains(lower, "curl/"):
		return "curl"
	case ua == "":
		return "Unknown"
	default:
		// Return first token (up to 20 chars) as fallback
		if idx := strings.IndexByte(ua, ' '); idx > 0 && idx <= 20 {
			return ua[:idx]
		}
		if len(ua) > 20 {
			return ua[:20]
		}
		return ua
	}
}
