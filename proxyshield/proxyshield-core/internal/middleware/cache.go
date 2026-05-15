package middleware

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

// CachedResponse holds a single stored backend response.
type CachedResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	CachedAt   time.Time
	TTL        time.Duration
}

func (c *CachedResponse) isExpired() bool {
	return time.Now().After(c.CachedAt.Add(c.TTL))
}

// ResponseRecorder buffers a backend response so we can add headers (e.g.
// X-ProxyShield-Cache: MISS) before writing to the real client.
// It does NOT forward to the underlying writer until Flush is called.
type ResponseRecorder struct {
	underlying  http.ResponseWriter
	statusCode  int
	body        bytes.Buffer
	wroteHeader bool
}

// NewResponseRecorder wraps w in a ResponseRecorder.
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{underlying: w, statusCode: http.StatusOK}
}

// Header returns the underlying writer's header map so the forwarder can set
// response headers directly on the real writer.
func (r *ResponseRecorder) Header() http.Header { return r.underlying.Header() }

// WriteHeader captures the status code without forwarding to the underlying writer.
func (r *ResponseRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.statusCode = code
		r.wroteHeader = true
	}
}

// Write buffers the body without forwarding to the underlying writer.
func (r *ResponseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.statusCode = http.StatusOK
		r.wroteHeader = true
	}
	return r.body.Write(b)
}

// StatusCode returns the captured HTTP status code.
func (r *ResponseRecorder) StatusCode() int { return r.statusCode }

// Flush writes the buffered response to the underlying writer, adding the given
// cache status header (e.g. "MISS") before calling WriteHeader.
func (r *ResponseRecorder) Flush(cacheStatus string) {
	r.underlying.Header().Set("X-ProxyShield-Cache", cacheStatus)
	r.underlying.WriteHeader(r.statusCode)
	r.underlying.Write(r.body.Bytes())
}

// ResponseCache caches successful GET/HEAD responses keyed by method+URI.
// Per-path TTL is configured via CacheConfig.Rules.
type ResponseCache struct {
	cache     sync.Map
	hitCount  int64
	missCount int64
}

// NewResponseCache creates a ResponseCache and starts a background eviction goroutine.
func NewResponseCache() *ResponseCache {
	rc := &ResponseCache{}
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			rc.evict()
		}
	}()
	return rc
}

func (rc *ResponseCache) evict() {
	rc.cache.Range(func(k, v interface{}) bool {
		if entry, ok := v.(*CachedResponse); ok && entry.isExpired() {
			rc.cache.Delete(k)
		}
		return true
	})
}

// findRule returns the first CacheRule that matches the request, or nil.
func (rc *ResponseCache) findRule(cfg *config.Config, r *http.Request) *config.CacheRule {
	if !cfg.Cache.Enabled {
		return nil
	}
	for i := range cfg.Cache.Rules {
		rule := &cfg.Cache.Rules[i]
		if rule.Path == r.URL.Path && strings.EqualFold(rule.Method, r.Method) {
			return rule
		}
	}
	return nil
}

// ServeFromCache writes a cached response to w and returns true if a valid
// (non-expired) entry exists. Returns false on miss.
func (rc *ResponseCache) ServeFromCache(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if rc.findRule(ctx.Config, r) == nil {
		return false
	}

	key := r.Method + ":" + r.URL.RequestURI()
	val, ok := rc.cache.Load(key)
	if !ok {
		atomic.AddInt64(&rc.missCount, 1)
		return false
	}
	entry := val.(*CachedResponse)
	if entry.isExpired() {
		rc.cache.Delete(key)
		atomic.AddInt64(&rc.missCount, 1)
		return false
	}

	atomic.AddInt64(&rc.hitCount, 1)

	for k, vals := range entry.Headers {
		for _, v := range vals {
			w.Header().Set(k, v)
		}
	}
	w.Header().Set("X-ProxyShield-Cache", "HIT")
	w.WriteHeader(entry.StatusCode)
	w.Write(entry.Body)

	if ctx.EventBus != nil {
		ctx.EventBus.Publish(event.Event{
			Name:      event.CacheHit,
			Data:      map[string]interface{}{"path": r.URL.Path, "method": r.Method},
			Timestamp: time.Now(),
		})
	}
	return true
}

// NewRecorder returns a ResponseRecorder for this request if a cache rule
// matches, otherwise nil. Use the returned recorder as the ResponseWriter
// when forwarding; call Flush+Store after the forwarder completes.
func (rc *ResponseCache) NewRecorder(w http.ResponseWriter, r *http.Request, ctx *reqctx.Context) *ResponseRecorder {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return nil
	}
	if rc.findRule(ctx.Config, r) == nil {
		return nil
	}
	return NewResponseRecorder(w)
}

// Store saves the recorder's buffered response into the cache.
func (rc *ResponseCache) Store(r *http.Request, rec *ResponseRecorder, ctx *reqctx.Context) {
	rule := rc.findRule(ctx.Config, r)
	if rule == nil {
		return
	}
	key := r.Method + ":" + r.URL.RequestURI()

	// Snapshot response headers (minus our injected cache header).
	headers := rec.underlying.Header().Clone()
	headers.Del("X-ProxyShield-Cache")

	body := make([]byte, rec.body.Len())
	copy(body, rec.body.Bytes())

	rc.cache.Store(key, &CachedResponse{
		StatusCode: rec.statusCode,
		Headers:    headers,
		Body:       body,
		CachedAt:   time.Now(),
		TTL:        time.Duration(rule.TTLSeconds) * time.Second,
	})
}

// Stats returns cache hit and miss counts and the hit ratio.
func (rc *ResponseCache) Stats() (hits, misses int64, ratio float64) {
	h := atomic.LoadInt64(&rc.hitCount)
	m := atomic.LoadInt64(&rc.missCount)
	if total := h + m; total > 0 {
		ratio = float64(h) / float64(total)
	}
	return h, m, ratio
}
