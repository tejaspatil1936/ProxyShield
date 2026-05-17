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

// NewForwarder creates an httputil.ReverseProxy configured for the given backend URL.
// It streams request and response bodies without buffering and uses a pooled transport.
func NewForwarder(backendURL string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host

		// Preserve original path and query
		// (already set by caller — do not override)

		// X-Forwarded-For
		clientIP := req.RemoteAddr
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			req.Header.Set("X-Forwarded-For", clientIP)
		}
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", req.Host)
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
