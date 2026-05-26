package algorithm

import (
	"sync"
	"testing"
	"time"
)

func TestSlidingWindowAllowsUpToLimit(t *testing.T) {
	sw := NewSlidingWindow()
	const limit = 3
	for i := 0; i < limit; i++ {
		r := sw.Check("k", limit, 60)
		if !r.Allowed {
			t.Fatalf("request %d within limit should be allowed", i+1)
		}
		if want := limit - (i + 1); r.Remaining != want {
			t.Errorf("request %d: expected Remaining=%d, got %d", i+1, want, r.Remaining)
		}
	}
	if sw.Check("k", limit, 60).Allowed {
		t.Fatalf("request %d over limit should be denied", limit+1)
	}
}

func TestSlidingWindowKeysAreIndependent(t *testing.T) {
	sw := NewSlidingWindow()
	sw.Check("a", 1, 60)
	if sw.Check("a", 1, 60).Allowed {
		t.Fatal("key a should be exhausted at limit 1")
	}
	if !sw.Check("b", 1, 60).Allowed {
		t.Fatal("key b must be independent of a")
	}
}

func TestSlidingWindowResetsAfterWindow(t *testing.T) {
	sw := NewSlidingWindow()
	sw.Check("k", 2, 1)
	sw.Check("k", 2, 1)
	if sw.Check("k", 2, 1).Allowed {
		t.Fatal("should be denied once the 1s window is full")
	}
	time.Sleep(1100 * time.Millisecond)
	if !sw.Check("k", 2, 1).Allowed {
		t.Fatal("should be allowed again after the window slides past")
	}
}

func TestSlidingWindowConcurrentAccess(t *testing.T) {
	sw := NewSlidingWindow()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sw.Check("shared", 10000, 60)
		}()
	}
	wg.Wait()
}
