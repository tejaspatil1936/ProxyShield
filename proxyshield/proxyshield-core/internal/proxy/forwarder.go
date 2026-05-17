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
// the forwarder's Director so it can set an accurate X-Forwarded-For.
const clientIPKey contextKey = "proxyshield.clientIP"

// NewForwarder creates an httputil.ReverseProxy configured for the given backend URL.
// It streams request and response bodies without buffering and uses a pooled transport.
func NewForwarder(backendURL string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	proxy.Director = func(req *http.Request) {
		host := req.Host
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host

		// Preserve original path and query
		// (already set by caller — do not override)

		// Present the backend with the single client IP that ProxyShield actually
		// trusts (resolved via the trusted-proxy rules), replacing any
		// client-supplied X-Forwarded-For chain so the backend can't be fed a
		// spoofed value. Fall back to the direct peer's IP (without port).
		clientIP, _ := req.Context().Value(clientIPKey).(string)
		if clientIP == "" {
			if h, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				clientIP = h
			} else {
				clientIP = req.RemoteAddr
			}
		}
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("X-Real-IP", clientIP)

		// Reflect the scheme the client used to reach the proxy rather than a
		// hardcoded "http".
		proto := "http"
		if req.TLS != nil {
			proto = "https"
		}
		req.Header.Set("X-Forwarded-Proto", proto)
		req.Header.Set("X-Forwarded-Host", host)
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
