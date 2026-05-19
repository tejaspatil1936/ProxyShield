package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/algorithm"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/logger"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/middleware"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

// Server is the main proxy server.
type Server struct {
	config         *config.Holder
	eventBus       *event.Bus
	chain          []middleware.Middleware
	forwarder      *httputil.ReverseProxy
	banMap         *sync.Map
	tb             *algorithm.TokenBucket
	sw             *algorithm.SlidingWindow
	httpServer     *http.Server
	circuitBreaker  *middleware.CircuitBreaker
	cache           *middleware.ResponseCache
	adaptiveTracker *middleware.AdaptiveTracker
}

// NewServer creates a new proxy server with all dependencies wired up.
func NewServer(holder *config.Holder, bus *event.Bus) (*Server, error) {
	cfg := holder.Get()

	fwd, err := NewForwarder(cfg.Server.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("creating forwarder: %w", err)
	}

	banMap := &sync.Map{}
	tb := algorithm.NewTokenBucket()
	sw := algorithm.NewSlidingWindow()

	s := &Server{
		config:         holder,
		eventBus:       bus,
		forwarder:      fwd,
		banMap:         banMap,
		tb:             tb,
		sw:             sw,
		circuitBreaker:  middleware.NewCircuitBreaker(),
		cache:           middleware.NewResponseCache(),
		adaptiveTracker: middleware.NewAdaptiveTracker(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.ListenPort),
		Handler: mux,
		// Bound every phase of a connection so slow clients can't pin goroutines
		// (Slowloris). WriteTimeout is generous to allow legitimate slow backends
		// and streaming, while ReadHeaderTimeout kills header-dribbling attacks.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			tb.Cleanup(5 * time.Minute)
			sw.Cleanup(5 * time.Minute)
		}
	}()

	return s, nil
}

// Start begins listening on the configured port. Handles SIGINT/SIGTERM gracefully.
func (s *Server) Start() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		tls := s.config.Get().Server.TLS
		if tls.Enabled {
			logger.Info("proxy listening (TLS)", logger.F("addr", s.httpServer.Addr))
			if err := s.httpServer.ListenAndServeTLS(tls.CertFile, tls.KeyFile); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
			return
		}
		logger.Info("proxy listening", logger.F("addr", s.httpServer.Addr))
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		logger.Info("shutdown signal received", logger.F("signal", sig.String()))
		return s.Shutdown()
	}
}

// Shutdown gracefully stops the server with a 5-second timeout.
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

// GetBanMap returns the shared ban map (used by dashboard stats).
func (s *Server) GetBanMap() *sync.Map {
	return s.banMap
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	cfg := s.config.Get()
	ip := extractIP(r, cfg)
	// Carry the resolved client IP to the forwarder's Director for X-Forwarded-For.
	r = r.WithContext(context.WithValue(r.Context(), clientIPKey, ip))

	s.eventBus.Publish(event.Event{
		Name:      event.RequestReceived,
		Data:      map[string]interface{}{"ip": ip, "path": r.URL.Path, "method": r.Method},
		Timestamp: time.Now(),
	})

	var body []byte
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		if cl := r.ContentLength; cl > cfg.Security.MaxBodyBytes {
			writeBlockedJSON(w, http.StatusRequestEntityTooLarge, "OVERSIZED_PAYLOAD")
			s.eventBus.Publish(event.Event{
				Name:      event.RequestBlocked,
				Data:      map[string]interface{}{"ip": ip, "path": r.URL.Path, "threatTag": "OVERSIZED_PAYLOAD"},
				Timestamp: time.Now(),
			})
			return
		}

		limited := http.MaxBytesReader(w, r.Body, cfg.Security.MaxBodyBytes)
		var err error
		body, err = io.ReadAll(limited)
		if err != nil {
			writeBlockedJSON(w, http.StatusRequestEntityTooLarge, "OVERSIZED_PAYLOAD")
			s.eventBus.Publish(event.Event{
				Name:      event.RequestBlocked,
				Data:      map[string]interface{}{"ip": ip, "path": r.URL.Path, "threatTag": "OVERSIZED_PAYLOAD"},
				Timestamp: time.Now(),
			})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	ctx := &reqctx.Context{
		IP:        ip,
		Body:      body,
		BodyText:  string(body),
		StartTime: time.Now(),
		Config:    cfg,
		EventBus:  s.eventBus,
	}

	// Rebuild chain with current config on each request (supports hot reload)
	chain := middleware.BuildChain(cfg, s.banMap, s.tb, s.sw, s.adaptiveTracker)

	if middleware.RunChain(chain, w, r, ctx) {
		return
	}

	// Wrap with RateLimitResponseWriter when rate limit info is present.
	var responseWriter http.ResponseWriter = w
	if ctx.RateLimitInfo != nil {
		responseWriter = middleware.NewRateLimitResponseWriter(w, ctx.RateLimitInfo)
	}

	cbCfg := &cfg.CircuitBreaker

	// Serve from cache if a valid entry exists — skip backend entirely.
	if s.cache.ServeFromCache(responseWriter, r, ctx) {
		s.circuitBreaker.RecordSuccess(cbCfg, s.eventBus) // treat cache hit as backend success
		latency := time.Since(ctx.StartTime).Seconds() * 1000
		s.eventBus.Publish(event.Event{
			Name:      event.RequestForwarded,
			Data:      map[string]interface{}{"ip": ip, "path": r.URL.Path, "method": r.Method, "latency_ms": latency, "cached": true},
			Timestamp: time.Now(),
		})
		return
	}

	// Circuit breaker — reject immediately if backend is known-bad.
	if !s.circuitBreaker.Allow(cbCfg) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		data, _ := json.Marshal(map[string]string{
			"error":  "Service temporarily unavailable",
			"reason": "CIRCUIT_BREAKER_OPEN",
		})
		w.Write(data)
		s.eventBus.Publish(event.Event{
			Name:      event.RequestBlocked,
			Data:      map[string]interface{}{"ip": ip, "path": r.URL.Path, "threatTag": "CIRCUIT_BREAKER", "fingerprint": ctx.Fingerprint},
			Timestamp: time.Now(),
		})
		return
	}

	// Forward to backend, capturing status for circuit breaker and optionally
	// buffering the response for caching.
	recorder := s.cache.NewRecorder(responseWriter, r, ctx)
	var statusCode int

	if recorder != nil {
		// Cache-eligible path: buffer response so we can add headers before sending.
		s.forwarder.ServeHTTP(recorder, r)
		statusCode = recorder.StatusCode()
		recorder.Flush("MISS")
		if statusCode < 500 {
			s.cache.Store(r, recorder, ctx)
		}
	} else {
		// Normal path: pass-through with status capture only.
		sc := middleware.NewStatusCapture(responseWriter)
		s.forwarder.ServeHTTP(sc, r)
		statusCode = sc.StatusCode()
	}

	if statusCode >= 500 {
		s.circuitBreaker.RecordFailure(cbCfg, s.eventBus)
	} else {
		s.circuitBreaker.RecordSuccess(cbCfg, s.eventBus)
	}

	latency := time.Since(ctx.StartTime).Seconds() * 1000
	s.eventBus.Publish(event.Event{
		Name:      event.RequestForwarded,
		Data:      map[string]interface{}{"ip": ip, "path": r.URL.Path, "method": r.Method, "latency_ms": latency},
		Timestamp: time.Now(),
	})
	logger.Info("request forwarded",
		logger.F("ip", ip),
		logger.F("path", r.URL.Path),
		logger.F("latency_ms", latency),
	)
}

// extractIP returns the trustworthy client IP for the request.
//
// X-Forwarded-For is honored ONLY when the direct peer (RemoteAddr) is itself a
// configured trusted proxy; otherwise the header is attacker-controlled and is
// ignored in favor of RemoteAddr. When trusted, the chain is walked right-to-left
// skipping trusted hops, and the first untrusted address is the real client. This
// prevents an attacker from forging a fresh identity per request by rotating XFF,
// which would otherwise defeat the blacklist, rate limiter, adaptive baselines,
// and bans simultaneously.
func extractIP(r *http.Request, cfg *config.Config) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.TrimPrefix(host, "::ffff:")

	peer := net.ParseIP(host)
	if peer == nil || cfg == nil || !cfg.IsTrustedProxy(peer) {
		return host
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		cand := strings.TrimSpace(parts[i])
		cand = strings.TrimPrefix(cand, "::ffff:")
		ip := net.ParseIP(cand)
		if ip == nil {
			continue
		}
		if cfg.IsTrustedProxy(ip) {
			continue // another trusted hop — keep walking left
		}
		return cand // first untrusted address = real client
	}
	// Entire chain was trusted (or unparseable) — fall back to the direct peer.
	return host
}

// writeBlockedJSON writes a 4xx JSON error response.
func writeBlockedJSON(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	data, _ := json.Marshal(map[string]string{"error": "Request rejected", "reason": reason})
	w.Write(data)
}
