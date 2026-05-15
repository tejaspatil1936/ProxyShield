// Command proxyshield is the entry point for the ProxyShield reverse proxy.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/benchmark"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/dashboard"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/logger"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/proxy"
)

// Set via ldflags at build time by GoReleaser.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	verbose := flag.Bool("verbose", false, "enable debug logging")
	showVersion := flag.Bool("version", false, "print version and exit")
	doBenchmark := flag.Bool("benchmark", false, "run benchmark mode")
	requests := flag.Int("requests", 10000, "benchmark request count")
	concurrency := flag.Int("concurrency", 100, "benchmark concurrency")
	flag.Parse()

	if *showVersion {
		fmt.Printf("proxyshield %s (commit %s)\n", version, commit)
		return
	}

	logger.SetVerbose(*verbose)

	if *doBenchmark {
		// Silence per-request logs during benchmark — only print the results table.
		logger.SetVerbose(false)
		logger.Silence(true)
		if err := benchmark.Run(*configPath, *requests, *concurrency); err != nil {
			logger.Silence(false)
			logger.Error("benchmark failed", logger.F("error", err.Error()))
			os.Exit(1)
		}
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", logger.F("path", *configPath), logger.F("error", err.Error()))
		os.Exit(1)
	}

	// Railway sets PORT — override config so the proxy binds to the assigned port.
	if envPort := os.Getenv("PORT"); envPort != "" {
		if port, err := strconv.Atoi(envPort); err == nil {
			cfg.Server.ListenPort = port
			cfg.Server.DashboardPort = port + 1
		}
	}

	bus := event.NewBus(10000)
	holder := config.NewHolder()
	holder.Set(cfg)

	go config.Watch(*configPath, holder, bus)

	server, err := proxy.NewServer(holder, bus)
	if err != nil {
		logger.Error("failed to create proxy server", logger.F("error", err.Error()))
		os.Exit(1)
	}

	printBanner(cfg)

	// Start dashboard if enabled
	if cfg.Dashboard.Enabled {
		dash := dashboard.NewDashboardServerOnPort(bus, server.GetBanMap(), cfg.Server.DashboardPort)
		go func() {
			if err := dash.Start(bus); err != nil {
				logger.Error("dashboard error", logger.F("error", err.Error()))
			}
		}()
	}

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info("shutting down")
		server.Shutdown()
	}()

	if err := server.Start(); err != nil {
		logger.Error("proxy server error", logger.F("error", err.Error()))
		os.Exit(1)
	}
}

func printBanner(cfg *config.Config) {
	fmt.Println(`╔══════════════════════════════════════════╗`)
	fmt.Printf( "║         ProxyShield %-21s║\n", version)
	fmt.Println(`║   High-Performance Reverse Proxy (Go)    ║`)
	fmt.Println(`╠══════════════════════════════════════════╣`)
	fmt.Printf( "║  Proxy:      http://localhost:%-12d║\n", cfg.Server.ListenPort)
	fmt.Printf( "║  Backend:    %-28s║\n", cfg.Server.BackendURL)
	fmt.Printf( "║  Dashboard:  http://localhost:%-12d║\n", cfg.Server.DashboardPort)
	fmt.Printf( "║  Middlewares: %-26d║\n", len(cfg.Middlewares))
	fmt.Println(`║  Algorithms:  token_bucket, sliding_window║`)
	fmt.Println(`╚══════════════════════════════════════════╝`)
}
