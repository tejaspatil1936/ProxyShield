package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
}

// NewDashboardServerOnPort creates a DashboardServer on a specific port.
func NewDashboardServerOnPort(bus *event.Bus, banMap *sync.Map, port int) *DashboardServer {
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
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", broker.ServeHTTP)
	mux.HandleFunc("/stats", stats.ServeHTTP)
	mux.HandleFunc("/style.css", d.serveStatic("style.css", "text/css"))
	mux.HandleFunc("/app.js", d.serveStatic("app.js", "application/javascript"))
	mux.HandleFunc("/dashboard", d.serveIndex)
	mux.HandleFunc("/", d.serveIndex)

	d.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
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
