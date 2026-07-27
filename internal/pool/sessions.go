// Package pool decides which tor instance carries a caller's traffic, keeps
// callers pinned to their instance, and tracks how well each instance behaves.
package pool

import (
	"sync"
	"time"
)

// Session is one caller's pinning to an instance.
//
// A session is an identity hint, not a security boundary: many callers may
// present the same key, and they then deliberately share an instance.
type Session struct {
	Key       string    `json:"key"`
	Instance  int       `json:"instance"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	Requests  int64     `json:"requests"`
	Failures  int64     `json:"failures"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
	Active    int       `json:"active"`
}

// sessions is the pinning table.
//
// Keys arrive from untrusted input (a SOCKS5 username), so the table is bounded:
// without a cap, a caller cycling keys would grow it without limit.
type sessions struct {
	mu    sync.Mutex
	byKey map[string]*Session
	ttl   time.Duration
	max   int
}

func newSessions(ttl time.Duration, maxEntries int) *sessions {
	return &sessions{
		byKey: make(map[string]*Session),
		ttl:   ttl,
		max:   maxEntries,
	}
}

// lookup returns a copy of the session for key, if one is pinned.
func (s *sessions) lookup(key string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byKey[key]
	if !ok {
		return Session{}, false
	}
	return *sess, true
}

// pin assigns key to an instance, creating the session if needed. It reports
// whether the assignment changed.
func (s *sessions) pin(key string, instance int, now time.Time) (changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.byKey[key]
	if !ok {
		s.evictIfFullLocked(now)
		s.byKey[key] = &Session{
			Key:       key,
			Instance:  instance,
			CreatedAt: now,
			LastSeen:  now,
		}
		return true
	}

	changed = sess.Instance != instance
	sess.Instance = instance
	sess.LastSeen = now
	return changed
}

// evictIfFullLocked makes room for a new session by dropping the least recently
// seen one. Callers must hold the lock.
func (s *sessions) evictIfFullLocked(now time.Time) {
	if len(s.byKey) < s.max {
		return
	}
	// Expired entries first — they are free to drop.
	for key, sess := range s.byKey {
		if now.Sub(sess.LastSeen) > s.ttl {
			delete(s.byKey, key)
		}
	}
	if len(s.byKey) < s.max {
		return
	}

	var (
		oldestKey  string
		oldestSeen time.Time
	)
	for key, sess := range s.byKey {
		if oldestKey == "" || sess.LastSeen.Before(oldestSeen) {
			oldestKey, oldestSeen = key, sess.LastSeen
		}
	}
	if oldestKey != "" {
		delete(s.byKey, oldestKey)
	}
}

// begin marks the start of a request on a session and returns the instance it
// is pinned to.
func (s *sessions) begin(key string, now time.Time) (instance int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byKey[key]
	if !ok {
		return 0, false
	}
	sess.LastSeen = now
	sess.Requests++
	sess.Active++
	return sess.Instance, true
}

// finish records the end of a request.
func (s *sessions) finish(key string, up, down int64, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byKey[key]
	if !ok {
		return
	}
	if sess.Active > 0 {
		sess.Active--
	}
	sess.BytesUp += up
	sess.BytesDown += down
	if failed {
		sess.Failures++
	}
}

// recordFailure attributes a client-reported failure to a session.
func (s *sessions) recordFailure(key string) (instance int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byKey[key]
	if !ok {
		return 0, false
	}
	sess.Failures++
	sess.LastSeen = time.Now()
	return sess.Instance, true
}

// drop removes a session's pinning.
func (s *sessions) drop(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.byKey[key]
	delete(s.byKey, key)
	return ok
}

// list returns a snapshot of all sessions.
func (s *sessions) list() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.byKey))
	for _, sess := range s.byKey {
		out = append(out, *sess)
	}
	return out
}

// countByInstance returns how many sessions are pinned to each instance. It is
// the input to load-based assignment.
func (s *sessions) countByInstance() map[int]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := make(map[int]int, len(s.byKey))
	for _, sess := range s.byKey {
		counts[sess.Instance]++
	}
	return counts
}

// unpinInstance clears the pinning of every session on an instance, so their
// next request is reassigned. Returns how many were moved.
//
// Sessions are unpinned rather than reassigned immediately: picking now would
// crowd every displaced session onto whichever instance looks least loaded at
// this instant, while doing it lazily spreads them as they return.
func (s *sessions) unpinInstance(instance int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for key, sess := range s.byKey {
		if sess.Instance == instance {
			delete(s.byKey, key)
			n++
		}
	}
	return n
}

// sweep drops sessions idle for longer than the TTL and returns how many went.
func (s *sessions) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for key, sess := range s.byKey {
		// A session with traffic in flight is never idle, however old.
		if sess.Active == 0 && now.Sub(sess.LastSeen) > s.ttl {
			delete(s.byKey, key)
			n++
		}
	}
	return n
}

// count returns the number of live sessions.
func (s *sessions) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byKey)
}
