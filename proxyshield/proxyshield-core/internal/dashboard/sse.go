// Package dashboard provides the real-time monitoring dashboard server.
package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
)

// SSEBroker manages SSE client connections and fans out events to all connected clients.
type SSEBroker struct {
	clients    map[chan []byte]bool
	mu         sync.RWMutex
	register   chan chan []byte
	unregister chan chan []byte
	eventBus   *event.Bus
}

// NewSSEBroker creates a new SSEBroker connected to the given event bus.
func NewSSEBroker(bus *event.Bus) *SSEBroker {
	return &SSEBroker{
		clients:    make(map[chan []byte]bool),
		register:   make(chan chan []byte, 64),
		unregister: make(chan chan []byte, 64),
		eventBus:   bus,
	}
}

// Start subscribes to all events and broadcasts them to connected SSE clients.
// Run this in a goroutine.
func (b *SSEBroker) Start() {
	allEvents := b.eventBus.SubscribeAll()

	for {
		select {
		case ch := <-b.register:
			b.mu.Lock()
			b.clients[ch] = true
			b.mu.Unlock()

		case ch := <-b.unregister:
			b.mu.Lock()
			delete(b.clients, ch)
			b.mu.Unlock()
			close(ch)

		case evt := <-allEvents:
			data, err := json.Marshal(evt.Data)
			if err != nil {
				continue
			}
			msg := []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", evt.Name, data))

			b.mu.RLock()
			for ch := range b.clients {
				select {
				case ch <- msg:
				default:
					// Drop if client buffer full
				}
			}
			b.mu.RUnlock()
		}
	}
}

// ServeHTTP handles SSE client connections. Streams events until the client disconnects.
func (b *SSEBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	client := make(chan []byte, 256)
	b.register <- client

	// Send connected comment
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			b.unregister <- client
			return

		case <-heartbeat.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()

		case msg, ok := <-client:
			if !ok {
				return
			}
			w.Write(msg)
			flusher.Flush()
		}
	}
}
