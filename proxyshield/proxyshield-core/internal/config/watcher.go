package config

import (
	"os"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/logger"
)

// Watch polls the config file every 2 seconds for modifications.
// When a change is detected, it reloads and validates the config.
// Invalid configs are discarded — the previous config remains active.
// Runs indefinitely in the calling goroutine; launch with go Watch(...).
func Watch(path string, holder *Holder, eventBus *event.Bus) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	info, err := os.Stat(path)
	var lastMod time.Time
	if err == nil {
		lastMod = info.ModTime()
	}

	for range ticker.C {
		info, err := os.Stat(path)
		if err != nil {
			logger.Warn("config watcher: stat failed", logger.F("path", path), logger.F("error", err.Error()))
			continue
		}

		if !info.ModTime().After(lastMod) {
			continue
		}
		lastMod = info.ModTime()

		newCfg, err := Load(path)
		if err != nil {
			logger.Warn("config watcher: reload failed, keeping old config",
				logger.F("path", path),
				logger.F("error", err.Error()),
			)
			continue
		}

		old := holder.Get()
		holder.Set(newCfg)

		changes := diffConfigs(old, newCfg)
		logger.Info("config reloaded", logger.F("changes", changes))

		eventBus.Publish(event.Event{
			Name:      event.ConfigReloaded,
			Data:      map[string]interface{}{"path": path, "changes": changes},
			Timestamp: time.Now(),
		})
	}
}

// diffConfigs returns a human-readable summary of what changed between two configs.
func diffConfigs(old, newCfg *Config) []string {
	if old == nil {
		return []string{"initial load"}
	}
	var changes []string
	if old.Server.ListenPort != newCfg.Server.ListenPort {
		changes = append(changes, "server.listen_port changed")
	}
	if old.Server.BackendURL != newCfg.Server.BackendURL {
		changes = append(changes, "server.backend_url changed")
	}
	if len(old.RateLimits) != len(newCfg.RateLimits) {
		changes = append(changes, "rate_limits count changed")
	}
	if len(old.Honeypots) != len(newCfg.Honeypots) {
		changes = append(changes, "honeypots count changed")
	}
	if old.Security.EntropyThreshold != newCfg.Security.EntropyThreshold {
		changes = append(changes, "security.entropy_threshold changed")
	}
	if len(changes) == 0 {
		changes = []string{"minor changes"}
	}
	return changes
}
