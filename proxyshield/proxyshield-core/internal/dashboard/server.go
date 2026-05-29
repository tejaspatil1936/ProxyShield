package dashboard

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/logger"
)

// DashboardServer serves the real-time monitoring dashboard.
type DashboardServer struct {
	broker     *SSEBroker
	stats      *Stats
	httpServer *http.Server
	publicDir  string
	authToken  string
}

// NewDashboardServerOnPort creates a DashboardServer on a specific port. When
// authToken is non-empty, the data endpoints (/stats, /events) require it.
func NewDashboardServerOnPort(bus *event.Bus, banMap *sync.Map, port int, authToken string) *DashboardServer {
	broker := NewSSEBroker(bus)
	stats := NewStats(bus, banMap)

	exe, err := os.Executable()
	publicDir := "internal/dashboard/public"
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "internal", "dashboard", "public")
		if _, err := os.Stat(candidate); err == nil {
			publicDir = candidate
		}
	}

	d := &DashboardServer{
		broker:    broker,
		stats:     stats,
		publicDir: publicDir,
		authToken: authToken,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", d.requireAuth(broker.ServeHTTP))
	mux.HandleFunc("/stats", d.requireAuth(stats.ServeHTTP))
	mux.HandleFunc("/metrics", d.requireAuth(stats.ServePrometheus))
	mux.HandleFunc("/style.css", d.serveStatic("style.css", "text/css"))
	mux.HandleFunc("/app.js", d.serveStatic("app.js", "application/javascript"))
	mux.HandleFunc("/dashboard", d.serveIndex)
	mux.HandleFunc("/", d.serveIndex)

	d.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
		// ReadHeaderTimeout guards against slow-header attacks. WriteTimeout is
		// intentionally 0 (unbounded): /events is a long-lived SSE stream that a
		// hard write deadline would sever. IdleTimeout still reaps idle keep-alives.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return d
}

// Start launches the SSE broker, stats collector, and HTTP server.
func (d *DashboardServer) Start(bus *event.Bus) error {
	go d.broker.Start()
	go d.stats.Start(bus)

	logger.Info("dashboard listening", logger.F("addr", d.httpServer.Addr))
	if err := d.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the dashboard server.
func (d *DashboardServer) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.httpServer.Shutdown(ctx)
}

// requireAuth wraps a handler so that, when an auth token is configured, the
// request must present it via "Authorization: Bearer <token>" or "?token=".
// Comparison is constant-time. With no token configured, the handler is public.
func (d *DashboardServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.authToken != "" && !d.tokenOK(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized","reason":"dashboard token required"}`))
			return
		}
		next(w, r)
	}
}

func (d *DashboardServer) tokenOK(r *http.Request) bool {
	got := r.URL.Query().Get("token")
	if got == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			got = strings.TrimPrefix(h, "Bearer ")
		}
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(d.authToken)) == 1
}

func (d *DashboardServer) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}
	d.serveFile(w, r, "index.html", "text/html")
}

func (d *DashboardServer) serveStatic(filename, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d.serveFile(w, r, filename, contentType)
	}
}

func (d *DashboardServer) serveFile(w http.ResponseWriter, r *http.Request, filename, contentType string) {
	paths := []string{
		filepath.Join(d.publicDir, filename),
		filepath.Join("internal", "dashboard", "public", filename),
		filepath.Join("proxyshield-core", "internal", "dashboard", "public", filename),
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			w.Header().Set("Content-Type", contentType)
			w.Write(data)
			return
		}
	}

	http.NotFound(w, r)
}
