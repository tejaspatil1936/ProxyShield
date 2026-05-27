package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

func cacheCtx() *reqctx.Context {
	cfg := &config.Config{}
	cfg.Cache.Enabled = true
	cfg.Cache.Rules = []config.CacheRule{{Path: "/data", Method: "GET", TTLSeconds: 60}}
	return &reqctx.Context{Config: cfg, EventBus: event.NewBus(16)}
}

func TestCacheStoresAndServes200(t *testing.T) {
	rc := NewResponseCache()
	ctx := cacheCtx()
	r := httptest.NewRequest("GET", "/data", nil)

	rec := rc.NewRecorder(httptest.NewRecorder(), r, ctx)
	if rec == nil {
		t.Fatal("expected a recorder for a cacheable GET")
	}
	rec.WriteHeader(200)
	rec.Write([]byte("hello"))
	rec.Flush("MISS")
	rc.Store(r, rec, ctx)

	w := httptest.NewRecorder()
	if !rc.ServeFromCache(w, r, ctx) {
		t.Fatal("expected a cache hit on the second request")
	}
	if w.Body.String() != "hello" {
		t.Errorf("cached body mismatch: got %q", w.Body.String())
	}
	if w.Header().Get("X-ProxyShield-Cache") != "HIT" {
		t.Error("expected X-ProxyShield-Cache: HIT")
	}
}

func TestCacheSkipsCredentialedRequest(t *testing.T) {
	rc := NewResponseCache()
	ctx := cacheCtx()
	r := httptest.NewRequest("GET", "/data", nil)
	r.Header.Set("Authorization", "Bearer secret")

	if rc.NewRecorder(httptest.NewRecorder(), r, ctx) != nil {
		t.Fatal("a credentialed request must not be recorded for caching")
	}
	if rc.ServeFromCache(httptest.NewRecorder(), r, ctx) {
		t.Fatal("a credentialed request must never be served from the shared cache")
	}
}

func TestCacheDoesNotStore4xx(t *testing.T) {
	rc := NewResponseCache()
	ctx := cacheCtx()
	r := httptest.NewRequest("GET", "/data", nil)

	rec := rc.NewRecorder(httptest.NewRecorder(), r, ctx)
	rec.WriteHeader(403)
	rec.Write([]byte("forbidden"))
	rc.Store(r, rec, ctx)

	if rc.ServeFromCache(httptest.NewRecorder(), r, ctx) {
		t.Fatal("4xx responses must not be cached")
	}
}

func TestCacheDoesNotStoreSetCookie(t *testing.T) {
	rc := NewResponseCache()
	ctx := cacheCtx()
	r := httptest.NewRequest("GET", "/data", nil)

	rec := rc.NewRecorder(httptest.NewRecorder(), r, ctx)
	rec.Header().Set("Set-Cookie", "session=secret")
	rec.WriteHeader(200)
	rec.Write([]byte("ok"))
	rc.Store(r, rec, ctx)

	if rc.ServeFromCache(httptest.NewRecorder(), r, ctx) {
		t.Fatal("responses carrying Set-Cookie must not be cached (session leakage)")
	}
}
