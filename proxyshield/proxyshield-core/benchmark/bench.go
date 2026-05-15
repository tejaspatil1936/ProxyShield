// Package benchmark provides a built-in self-benchmark for ProxyShield.
package benchmark

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/proxy"
)

// Run starts a self-benchmark: spins up a dummy backend, starts the proxy,
// fires numRequests concurrent requests, and prints latency distribution results.
func Run(configPath string, numRequests int, concurrency int) error {
	// Start a dummy backend on a random port
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("starting backend listener: %w", err)
	}
	backendPort := backendLn.Addr().(*net.TCPAddr).Port
	backendURL := fmt.Sprintf("http://127.0.0.1:%d", backendPort)

	backendServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			data, _ := json.Marshal(map[string]bool{"ok": true})
			w.Write(data)
		}),
	}
	go backendServer.Serve(backendLn)

	// Load and override config
	cfg, err := config.Load(configPath)
	if err != nil {
		// Use minimal default config for benchmark
		cfg = &config.Config{
			Server: config.ServerConfig{
				ListenPort:    0,
				BackendURL:    backendURL,
				DashboardPort: 0,
			},
			Middlewares: []string{},
		}
	}
	cfg.Server.BackendURL = backendURL

	// Find a free port for the proxy
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("starting proxy listener: %w", err)
	}
	proxyPort := proxyLn.Addr().(*net.TCPAddr).Port
	proxyLn.Close()
	cfg.Server.ListenPort = proxyPort
	cfg.Server.DashboardPort = proxyPort + 1

	bus := event.NewBus(10000)
	holder := config.NewHolder()
	holder.Set(cfg)

	server, err := proxy.NewServer(holder, bus)
	if err != nil {
		return fmt.Errorf("creating proxy server: %w", err)
	}

	go server.Start()
	time.Sleep(200 * time.Millisecond)

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d/bench", proxyPort)

	var (
		mu        sync.Mutex
		latencies []float64
		successes int
		failures  int
		wg        sync.WaitGroup
	)

	sem := make(chan struct{}, concurrency)
	start := time.Now()

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			t0 := time.Now()
			resp, err := http.Get(proxyURL)
			elapsed := time.Since(t0).Seconds() * 1000

			mu.Lock()
			if err != nil || resp.StatusCode >= 500 {
				failures++
			} else {
				successes++
				latencies = append(latencies, elapsed)
			}
			mu.Unlock()

			if resp != nil {
				resp.Body.Close()
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	server.Shutdown()
	backendServer.Close()

	printResults(numRequests, successes, failures, duration, latencies)
	return nil
}

func printResults(total, successes, failures int, duration time.Duration, latencies []float64) {
	throughput := float64(successes) / duration.Seconds()

	sort.Float64s(latencies)

	pct := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(float64(len(latencies)) * p / 100)
		if idx >= len(latencies) {
			idx = len(latencies) - 1
		}
		return latencies[idx]
	}

	avg := func() float64 {
		if len(latencies) == 0 {
			return 0
		}
		var sum float64
		for _, v := range latencies {
			sum += v
		}
		return sum / float64(len(latencies))
	}()

	var minL, maxL float64
	if len(latencies) > 0 {
		minL = latencies[0]
		maxL = latencies[len(latencies)-1]
	}

	fmt.Println(`╔══════════════════════════════════════╗`)
	fmt.Println(`║   ProxyShield Benchmark Results     ║`)
	fmt.Println(`╠══════════════════════════════════════╣`)
	fmt.Printf( "║  Total requests:  %-18s║\n", fmt.Sprintf("%d", total))
	fmt.Printf( "║  Successful:      %-18s║\n", fmt.Sprintf("%d", successes))
	fmt.Printf( "║  Failed:          %-18s║\n", fmt.Sprintf("%d", failures))
	fmt.Printf( "║  Duration:        %-18s║\n", fmt.Sprintf("%.2fs", duration.Seconds()))
	fmt.Printf( "║  Throughput:      %-18s║\n", fmt.Sprintf("%.0f req/s", throughput))
	fmt.Println(`║                                     ║`)
	fmt.Println(`║  Latency Distribution:              ║`)
	fmt.Printf( "║    min:  %-27s║\n", fmt.Sprintf("%.1fms", minL))
	fmt.Printf( "║    avg:  %-27s║\n", fmt.Sprintf("%.1fms", avg))
	fmt.Printf( "║    p50:  %-27s║\n", fmt.Sprintf("%.1fms", pct(50)))
	fmt.Printf( "║    p95:  %-27s║\n", fmt.Sprintf("%.1fms", pct(95)))
	fmt.Printf( "║    p99:  %-27s║\n", fmt.Sprintf("%.1fms", pct(99)))
	fmt.Printf( "║    max:  %-27s║\n", fmt.Sprintf("%.1fms", maxL))
	fmt.Println(`╚══════════════════════════════════════╝`)
}
