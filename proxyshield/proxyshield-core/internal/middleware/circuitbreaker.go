package middleware

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
)

// Circuit breaker states.
const (
	StateClosed   int32 = 0
	StateOpen     int32 = 1
	StateHalfOpen int32 = 2
)

// CircuitBreaker is a lock-free atomic state machine that protects the backend
// from repeated failures. States: CLOSED → OPEN → HALF_OPEN → CLOSED.
//
// All fields are accessed via sync/atomic — no mutex required.
type CircuitBreaker struct {
	state           int32 // 0=closed, 1=open, 2=half-open
	failureCount    int32
	successCount    int32
	lastFailureTime int64 // Unix timestamp
}

// NewCircuitBreaker creates a CircuitBreaker in the CLOSED state.
func NewCircuitBreaker() *CircuitBreaker { return &CircuitBreaker{} }

// Allow returns true if the request should be forwarded to the backend.
// If the circuit is OPEN and the cooldown has not passed, returns false.
// A CLOSED→HALF_OPEN transition resets successCount atomically.
func (cb *CircuitBreaker) Allow(cfg *config.CircuitBreakerConfig) bool {
	if !cfg.Enabled {
		return true
	}
	switch atomic.LoadInt32(&cb.state) {
	case StateClosed:
		return true
	case StateOpen:
		last := atomic.LoadInt64(&cb.lastFailureTime)
		if time.Now().Unix()-last >= int64(cfg.CooldownSeconds) {
			// Transition to HALF_OPEN — let one probe request through.
			if atomic.CompareAndSwapInt32(&cb.state, StateOpen, StateHalfOpen) {
				atomic.StoreInt32(&cb.successCount, 0)
			}
			return true
		}
		return false
	default: // HALF_OPEN
		return true
	}
}

// RecordSuccess is called after a 2xx/3xx response from the backend.
func (cb *CircuitBreaker) RecordSuccess(cfg *config.CircuitBreakerConfig, bus *event.Bus) {
	if !cfg.Enabled {
		return
	}
	switch atomic.LoadInt32(&cb.state) {
	case StateClosed:
		atomic.StoreInt32(&cb.failureCount, 0)
	case StateHalfOpen:
		n := atomic.AddInt32(&cb.successCount, 1)
		if int(n) >= cfg.SuccessThreshold {
			atomic.StoreInt32(&cb.state, StateClosed)
			atomic.StoreInt32(&cb.failureCount, 0)
			atomic.StoreInt32(&cb.successCount, 0)
			if bus != nil {
				bus.Publish(event.Event{
					Name:      event.CircuitClosed,
					Data:      map[string]interface{}{"successCount": n},
					Timestamp: time.Now(),
				})
			}
		}
	}
}

// RecordFailure is called after a 5xx response from the backend.
func (cb *CircuitBreaker) RecordFailure(cfg *config.CircuitBreakerConfig, bus *event.Bus) {
	if !cfg.Enabled {
		return
	}
	switch atomic.LoadInt32(&cb.state) {
	case StateClosed:
		n := atomic.AddInt32(&cb.failureCount, 1)
		if int(n) >= cfg.FailureThreshold {
			if atomic.CompareAndSwapInt32(&cb.state, StateClosed, StateOpen) {
				atomic.StoreInt64(&cb.lastFailureTime, time.Now().Unix())
				if bus != nil {
					bus.Publish(event.Event{
						Name:      event.CircuitOpened,
						Data:      map[string]interface{}{"failureCount": n},
						Timestamp: time.Now(),
					})
				}
			}
		}
	case StateHalfOpen:
		// Probe failed — reopen.
		if atomic.CompareAndSwapInt32(&cb.state, StateHalfOpen, StateOpen) {
			atomic.StoreInt64(&cb.lastFailureTime, time.Now().Unix())
			if bus != nil {
				bus.Publish(event.Event{
					Name:      event.CircuitOpened,
					Data:      map[string]interface{}{"failureCount": atomic.LoadInt32(&cb.failureCount)},
					Timestamp: time.Now(),
				})
			}
		}
	}
}

// State returns the current circuit state as a string.
func (cb *CircuitBreaker) State() string {
	switch atomic.LoadInt32(&cb.state) {
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "CLOSED"
	}
}

// StatusCapture wraps a ResponseWriter to capture the HTTP status code
// while passing all writes through to the underlying writer unchanged.
type StatusCapture struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

// NewStatusCapture wraps w with a StatusCapture.
func NewStatusCapture(w http.ResponseWriter) *StatusCapture {
	return &StatusCapture{ResponseWriter: w}
}

func (s *StatusCapture) WriteHeader(code int) {
	if !s.wroteHeader {
		s.statusCode = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *StatusCapture) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.statusCode = http.StatusOK
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// StatusCode returns the captured HTTP status code (defaults to 200 if never set).
func (s *StatusCapture) StatusCode() int {
	if s.statusCode == 0 {
		return http.StatusOK
	}
	return s.statusCode
}

// Flush forwards to the underlying writer so streaming/SSE responses are not
// buffered. Implements http.Flusher.
func (s *StatusCapture) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying writer so WebSocket/other upgrades work.
// Implements http.Hijacker.
func (s *StatusCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := s.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("underlying ResponseWriter does not support hijacking")
}
