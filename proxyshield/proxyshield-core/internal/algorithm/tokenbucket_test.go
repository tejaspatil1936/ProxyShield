package algorithm

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucketAllowsBurstUpToLimit(t *testing.T) {
	tb := NewTokenBucket()
	const limit = 5
	for i := 0; i < limit; i++ {
		if r := tb.Check("k", limit, 60); !r.Allowed {
			t.Fatalf("request %d within limit should be allowed", i+1)
		}
	}
	r := tb.Check("k", limit, 60)
	if r.Allowed {
		t.Fatalf("request %d over limit should be denied", limit+1)
	}
	if r.Remaining != 0 {
		t.Errorf("expected 0 remaining when denied, got %d", r.Remaining)
	}
	if r.Limit != limit {
		t.Errorf("expected Limit=%d, got %d", limit, r.Limit)
	}
}

func TestTokenBucketKeysAreIndependent(t *testing.T) {
	tb := NewTokenBucket()
	for i := 0; i < 3; i++ {
		tb.Check("a", 3, 60)
	}
	if tb.Check("a", 3, 60).Allowed {
		t.Fatal("key a should be exhausted")
	}
	if !tb.Check("b", 3, 60).Allowed {
		t.Fatal("key b must be tracked independently of a")
	}
}

func TestTokenBucketRefillsOverTime(t *testing.T) {
	tb := NewTokenBucket()
	// 2 tokens per 1s window → refills 2 tokens/sec.
	tb.Check("k", 2, 1)
	tb.Check("k", 2, 1)
	if tb.Check("k", 2, 1).Allowed {
		t.Fatal("bucket should be exhausted after 2 immediate requests")
	}
	time.Sleep(1100 * time.Millisecond)
	if !tb.Check("k", 2, 1).Allowed {
		t.Fatal("bucket should refill after the window elapses")
	}
}

func TestTokenBucketCleanupRemovesStaleEntries(t *testing.T) {
	tb := NewTokenBucket()
	tb.Check("k", 5, 60)
	// maxAge 0 → any entry not accessed exactly now is stale.
	time.Sleep(2 * time.Millisecond)
	tb.Cleanup(1 * time.Millisecond)
	// A fresh entry starts at full tokens, so Current is 1 again.
	if r := tb.Check("k", 5, 60); r.Current != 1 {
		t.Errorf("expected a fresh entry (Current=1) after cleanup, got Current=%d", r.Current)
	}
}

func TestTokenBucketConcurrentAccess(t *testing.T) {
	tb := NewTokenBucket()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tb.Check("shared", 1000, 60)
		}()
	}
	wg.Wait() // -race verifies no data race on the shared entry
}
