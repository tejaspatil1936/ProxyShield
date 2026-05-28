package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwarderSetsResolvedXFFAndProto(t *testing.T) {
	var gotXFF, gotRealIP, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotRealIP = r.Header.Get("X-Real-IP")
		gotProto = r.Header.Get("X-Forwarded-Proto")
	}))
	defer backend.Close()

	fwd, err := NewForwarder(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.2:5555"
	r.Header.Set("X-Forwarded-For", "spoofed, 1.2.3.4") // must be replaced, not appended
	r = r.WithContext(context.WithValue(r.Context(), clientIPKey, "8.8.8.8"))

	fwd.ServeHTTP(httptest.NewRecorder(), r)

	if gotXFF != "8.8.8.8" {
		t.Errorf("X-Forwarded-For: got %q, want the resolved 8.8.8.8 (chain replaced)", gotXFF)
	}
	if gotRealIP != "8.8.8.8" {
		t.Errorf("X-Real-IP: got %q, want 8.8.8.8", gotRealIP)
	}
	if gotProto != "http" {
		t.Errorf("X-Forwarded-Proto: got %q, want http (non-TLS request)", gotProto)
	}
}

func TestForwarderFallsBackToRemoteAddrWithoutPort(t *testing.T) {
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
	}))
	defer backend.Close()

	fwd, _ := NewForwarder(backend.URL)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:9999"
	fwd.ServeHTTP(httptest.NewRecorder(), r)

	if gotXFF != "203.0.113.7" {
		t.Errorf("X-Forwarded-For: got %q, want the peer IP without port", gotXFF)
	}
}
