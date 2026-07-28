package auth

import (
	"sync"
	"time"
)

// limiter is a fixed-window failure counter, keyed by remote address.
//
// Two things about it are deliberate. The keys are untrusted input, so the map is
// capped and evicted rather than allowed to grow — the same argument that bounds
// the session table (invariant 11). And a caller over the limit is *refused*, not
// delayed: sleeping on the failure path would pin a goroutine per attempt and
// become the exhaustion it was added to prevent.
type limiter struct {
	limit  int
	window time.Duration
	cap    int

	mu    sync.Mutex
	seen  map[string]*bucket
	reset time.Time
}

type bucket struct {
	count int
	until time.Time
}

func newLimiter(limit int, window time.Duration, capacity int) *limiter {
	return &limiter{
		limit:  limit,
		window: window,
		cap:    capacity,
		seen:   make(map[string]*bucket),
		reset:  time.Now().Add(window),
	}
}

// blocked reports whether key has already used up its window, and how long is
// left. It counts nothing; call fail on an actual failure.
func (l *limiter) blocked(key string) (bool, time.Duration) {
	if l.limit <= 0 {
		return false, 0
	}
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)

	b := l.seen[key]
	if b == nil || b.count < l.limit || !now.Before(b.until) {
		return false, 0
	}
	return true, b.until.Sub(now)
}

// fail records one failed attempt for key.
func (l *limiter) fail(key string) {
	if l.limit <= 0 {
		return
	}
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)

	b := l.seen[key]
	if b == nil || !now.Before(b.until) {
		// Over capacity, drop the whole table rather than scan for a victim.
		// Losing counters costs an attacker nothing they did not already have,
		// and this path is only reachable by flooding from many addresses.
		if len(l.seen) >= l.cap {
			l.seen = make(map[string]*bucket)
		}
		b = &bucket{until: now.Add(l.window)}
		l.seen[key] = b
	}
	b.count++
}

// succeed clears a key's counter, so a correct login is not punished for earlier
// typos.
func (l *limiter) succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.seen, key)
}

// sweepLocked discards expired buckets, at most once per window.
func (l *limiter) sweepLocked(now time.Time) {
	if now.Before(l.reset) {
		return
	}
	l.reset = now.Add(l.window)
	for k, b := range l.seen {
		if !now.Before(b.until) {
			delete(l.seen, k)
		}
	}
}
