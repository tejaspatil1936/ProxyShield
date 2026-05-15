package middleware

import (
	"net/http"
	"strconv"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

// RateLimitResponseWriter wraps http.ResponseWriter to inject rate limit headers
// before the first write. Headers are set once when WriteHeader is called.
type RateLimitResponseWriter struct {
	http.ResponseWriter
	info          *reqctx.RateLimitInfo
	headerWritten bool
}

// NewRateLimitResponseWriter creates a new RateLimitResponseWriter.
func NewRateLimitResponseWriter(w http.ResponseWriter, info *reqctx.RateLimitInfo) *RateLimitResponseWriter {
	return &RateLimitResponseWriter{ResponseWriter: w, info: info}
}

// WriteHeader injects X-RateLimit headers before delegating to the underlying ResponseWriter.
func (rw *RateLimitResponseWriter) WriteHeader(statusCode int) {
	if !rw.headerWritten && rw.info != nil {
		rw.Header().Set("X-RateLimit-Limit", strconv.Itoa(rw.info.Limit))
		rw.Header().Set("X-RateLimit-Remaining", strconv.Itoa(rw.info.Remaining))
		rw.Header().Set("X-RateLimit-Reset", strconv.FormatInt(rw.info.ResetTime, 10))
		rw.headerWritten = true
	}
	rw.ResponseWriter.WriteHeader(statusCode)
}

// Write ensures headers are flushed before writing the body.
func (rw *RateLimitResponseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}
