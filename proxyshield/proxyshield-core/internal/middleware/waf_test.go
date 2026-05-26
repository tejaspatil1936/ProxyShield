package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/config"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"
)

func newTestWAF() *WAF {
	cfg := &config.Config{}
	cfg.Security.BlockSQLInjection = true
	cfg.Security.BlockXSS = true
	cfg.Security.EntropyThreshold = 5.5
	return NewWAF(cfg)
}

func wafCtx(body string) *reqctx.Context {
	return &reqctx.Context{IP: "1.2.3.4", Body: []byte(body), BodyText: body, EventBus: event.NewBus(16)}
}

func highEntropyBody(n int) string {
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(b64[i%len(b64)])
	}
	return b.String()
}

func TestWAFAllowsCleanRequest(t *testing.T) {
	waf := newTestWAF()
	r := httptest.NewRequest("GET", "/api/keys?q=hello", nil)
	if waf.Handle(httptest.NewRecorder(), r, wafCtx("")) {
		t.Fatal("a clean request must not be blocked")
	}
}

func TestWAFBlocksSQLInjectionInQuery(t *testing.T) {
	waf := newTestWAF()
	r := httptest.NewRequest("GET", "/search?q=1'%20UNION%20SELECT%20*%20FROM%20users--", nil)
	if !waf.Handle(httptest.NewRecorder(), r, wafCtx("")) {
		t.Fatal("SQL injection in query should be blocked")
	}
}

func TestWAFBlocksXSSInBody(t *testing.T) {
	waf := newTestWAF()
	r := httptest.NewRequest("POST", "/api/keys", nil)
	body := `{"name":"<script>alert(1)</script>"}`
	if !waf.Handle(httptest.NewRecorder(), r, wafCtx(body)) {
		t.Fatal("XSS in body should be blocked")
	}
}

func TestWAFBlocksUnicodeEscapedXSS(t *testing.T) {
	waf := newTestWAF()
	r := httptest.NewRequest("POST", "/api/keys", nil)
	// JSON-unicode encoded "<script>...</script>" — must be decoded before matching.
	body := "{\"name\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"}"
	if !waf.Handle(httptest.NewRecorder(), r, wafCtx(body)) {
		t.Fatal("unicode-escaped XSS should be caught by decode expansion")
	}
}

func TestWAFBlocksDoubleEncodedXSS(t *testing.T) {
	waf := newTestWAF()
	// %253Cscript%253E decodes once to %3Cscript%3E, then again to <script>.
	r := httptest.NewRequest("GET", "/search?q=%253Cscript%253Ealert%2528%2529%253C/script%253E", nil)
	if !waf.Handle(httptest.NewRecorder(), r, wafCtx("")) {
		t.Fatal("double-encoded XSS should be caught by multi-pass URL decode")
	}
}

func TestWAFScansHeaderValues(t *testing.T) {
	waf := newTestWAF()
	r := httptest.NewRequest("GET", "/api/keys", nil)
	r.Header.Set("Referer", "1' UNION SELECT password FROM secrets--")
	if !waf.Handle(httptest.NewRecorder(), r, wafCtx("")) {
		t.Fatal("SQL injection in a header value should be blocked")
	}
}

func TestWAFBlocksHighEntropyJSON(t *testing.T) {
	waf := newTestWAF()
	r := httptest.NewRequest("POST", "/api/scan", nil)
	r.Header.Set("Content-Type", "application/json")
	if !waf.Handle(httptest.NewRecorder(), r, wafCtx(highEntropyBody(700))) {
		t.Fatal("high-entropy body should be blocked")
	}
}

func TestWAFEntropyContentTypeBypassIsClosed(t *testing.T) {
	waf := newTestWAF()
	r := httptest.NewRequest("POST", "/api/scan", nil)
	// Claiming image/* must NOT disable the entropy check anymore.
	r.Header.Set("Content-Type", "image/png")
	if !waf.Handle(httptest.NewRecorder(), r, wafCtx(highEntropyBody(700))) {
		t.Fatal("image/* Content-Type must not bypass the entropy check")
	}
}

func TestWAFEntropySkippedForMultipartUpload(t *testing.T) {
	waf := newTestWAF()
	r := httptest.NewRequest("POST", "/upload", nil)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")
	if waf.Handle(httptest.NewRecorder(), r, wafCtx(highEntropyBody(700))) {
		t.Fatal("multipart/form-data uploads should be exempt from the entropy check")
	}
}
