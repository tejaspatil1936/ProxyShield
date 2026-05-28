package proxy

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/logger"
)

// contextKey is a private type for request-context keys set by the proxy.
type contextKey string

// clientIPKey carries the trusted, resolved client IP from handleRequest into
// the forwarder so it can set an accurate X-Forwarded-For.
const clientIPKey contextKey = "proxyshield.clientIP"

// NewForwarder creates an httputil.ReverseProxy configured for the given backend URL.
// It streams request and response bodies without buffering and uses a pooled transport.
func NewForwarder(backendURL string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}

	// Use Rewrite (not Director): Director would leave ReverseProxy's automatic
	// X-Forwarded-For appending in place, tacking the direct peer onto whatever we
	// set. Rewrite disables that, so the backend sees exactly the single trusted
	// client IP we choose — no spoofable chain.
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target) // scheme/host + path join to the backend
			pr.Out.Host = target.Host

			// The single client IP ProxyShield actually trusts (resolved via the
			// trusted-proxy rules), replacing any client-supplied XFF chain. Fall
			// back to the direct peer's IP (without port).
			clientIP, _ := pr.In.Context().Value(clientIPKey).(string)
			if clientIP == "" {
				if h, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
					clientIP = h
				} else {
					clientIP = pr.In.RemoteAddr
				}
			}
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
			pr.Out.Header.Set("X-Real-IP", clientIP)

			// Reflect the scheme the client used to reach the proxy, not a
			// hardcoded "http".
			proto := "http"
			if pr.In.TLS != nil {
				proto = "https"
			}
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("backend error", logger.F("error", err.Error()), logger.F("path", r.URL.Path))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		data, _ := json.Marshal(map[string]string{"error": "Backend unavailable"})
		w.Write(data)
	}

	proxy.Transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		// Bound backend handshake and time-to-first-byte so a hung or slow
		// backend can't tie up proxy connections indefinitely.
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return proxy, nil
}
