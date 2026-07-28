package pool

import (
	"slices"
	"testing"
	"time"
)

func TestPinIsSticky(t *testing.T) {
	s := newSessions(time.Minute, 100)
	now := time.Now()

	if changed := s.pin("a", 3, now); !changed {
		t.Error("first pin should report a change")
	}
	if changed := s.pin("a", 3, now); changed {
		t.Error("re-pinning to the same instance is not a change")
	}
	if changed := s.pin("a", 7, now); !changed {
		t.Error("moving to another instance is a change")
	}

	sess, ok := s.lookup("a")
	if !ok {
		t.Fatal("session should exist")
	}
	if sess.Instance != 7 {
		t.Errorf("Instance = %d, want 7", sess.Instance)
	}
}

func TestSharedKeyMeansSharedInstance(t *testing.T) {
	// Many callers presenting one key deliberately land on one instance.
	s := newSessions(time.Minute, 100)
	now := time.Now()
	s.pin("team", 2, now)
	s.pin("team", 2, now)

	if got := s.count(); got != 1 {
		t.Errorf("count = %d, want 1 — one key is one session", got)
	}
	if counts := s.countByInstance(); counts[2] != 1 {
		t.Errorf("instance 2 session count = %d, want 1", counts[2])
	}
}

func TestRequestAccounting(t *testing.T) {
	s := newSessions(time.Minute, 100)
	now := time.Now()
	s.pin("a", 1, now)

	instance, ok := s.begin("a", now)
	if !ok || instance != 1 {
		t.Fatalf("begin returned (%d, %v), want (1, true)", instance, ok)
	}

	sess, _ := s.lookup("a")
	if sess.Requests != 1 || sess.Active != 1 {
		t.Errorf("after begin: Requests=%d Active=%d, want 1 and 1", sess.Requests, sess.Active)
	}

	s.finish("a", 100, 900, false)
	sess, _ = s.lookup("a")
	if sess.Active != 0 {
		t.Errorf("Active = %d, want 0 after finish", sess.Active)
	}
	if sess.BytesUp != 100 || sess.BytesDown != 900 {
		t.Errorf("bytes = %d/%d, want 100/900", sess.BytesUp, sess.BytesDown)
	}
	if sess.Failures != 0 {
		t.Errorf("Failures = %d, want 0", sess.Failures)
	}

	s.begin("a", now)
	s.finish("a", 0, 0, true)
	sess, _ = s.lookup("a")
	if sess.Failures != 1 {
		t.Errorf("Failures = %d, want 1", sess.Failures)
	}
}

func TestBeginOnUnknownSession(t *testing.T) {
	s := newSessions(time.Minute, 100)
	if _, ok := s.begin("ghost", time.Now()); ok {
		t.Error("begin should report failure for an unpinned key")
	}
	// finish on an unknown key must not panic.
	s.finish("ghost", 1, 2, true)
}

func TestSweepDropsIdleSessions(t *testing.T) {
	s := newSessions(time.Minute, 100)
	past := time.Now().Add(-2 * time.Minute)
	s.pin("stale", 1, past)
	s.pin("fresh", 1, time.Now())

	if n := s.sweep(time.Now()); n != 1 {
		t.Errorf("sweep removed %d, want 1", n)
	}
	if _, ok := s.lookup("stale"); ok {
		t.Error("stale session should be gone")
	}
	if _, ok := s.lookup("fresh"); !ok {
		t.Error("fresh session should survive")
	}
}

func TestSweepKeepsSessionsWithTrafficInFlight(t *testing.T) {
	// A long download must not be unpinned mid-transfer just because the
	// session's last-seen timestamp is old.
	s := newSessions(time.Minute, 100)
	past := time.Now().Add(-2 * time.Minute)
	s.pin("busy", 1, past)
	s.begin("busy", past)

	if n := s.sweep(time.Now()); n != 0 {
		t.Errorf("sweep removed %d, want 0 while a request is active", n)
	}

	s.finish("busy", 0, 0, false)
	if n := s.sweep(time.Now()); n != 1 {
		t.Errorf("sweep removed %d, want 1 once idle", n)
	}
}

func TestTableIsBounded(t *testing.T) {
	// Keys are untrusted input: a caller cycling them must not grow the table
	// without limit.
	const max = 10
	s := newSessions(time.Hour, max)
	now := time.Now()

	for i := range 100 {
		s.pin(string(rune('a'+i%26))+string(rune('0'+i/26)), i, now.Add(time.Duration(i)*time.Second))
	}
	if got := s.count(); got > max {
		t.Errorf("count = %d, want at most %d", got, max)
	}
}

func TestEvictionPrefersLeastRecentlySeen(t *testing.T) {
	s := newSessions(time.Hour, 2)
	base := time.Now()

	s.pin("old", 1, base)
	s.pin("recent", 1, base.Add(time.Minute))
	s.pin("newest", 1, base.Add(2*time.Minute))

	if _, ok := s.lookup("old"); ok {
		t.Error("the least recently seen session should have been evicted")
	}
	if _, ok := s.lookup("newest"); !ok {
		t.Error("the newest session should be present")
	}
}

func TestUnpinInstanceMovesOnlyItsSessions(t *testing.T) {
	s := newSessions(time.Minute, 100)
	now := time.Now()
	s.pin("a", 1, now)
	s.pin("b", 1, now)
	s.pin("c", 2, now)

	if n := s.unpinInstance(1); n != 2 {
		t.Errorf("unpinned %d, want 2", n)
	}
	if _, ok := s.lookup("c"); !ok {
		t.Error("sessions on other instances must be untouched")
	}
	if _, ok := s.lookup("a"); ok {
		t.Error("session a should be unpinned")
	}
}

func TestRecordFailureAttributesToPinnedInstance(t *testing.T) {
	s := newSessions(time.Minute, 100)
	s.pin("a", 4, time.Now())

	instance, ok := s.recordFailure("a")
	if !ok || instance != 4 {
		t.Fatalf("recordFailure = (%d, %v), want (4, true)", instance, ok)
	}
	sess, _ := s.lookup("a")
	if sess.Failures != 1 {
		t.Errorf("Failures = %d, want 1", sess.Failures)
	}

	if _, ok := s.recordFailure("unknown"); ok {
		t.Error("recordFailure should report failure for an unknown key")
	}
}

func TestDrop(t *testing.T) {
	s := newSessions(time.Minute, 100)
	s.pin("a", 1, time.Now())

	if !s.drop("a") {
		t.Error("drop should report that it removed something")
	}
	if s.drop("a") {
		t.Error("dropping twice should report nothing removed")
	}
}

func TestListIsOrderedByKey(t *testing.T) {
	// Go randomises map iteration, and this snapshot feeds a table the dashboard
	// re-polls every few seconds: an unstable order reshuffles the rows under the
	// operator, so a click lands on whichever session moved into that row.
	s := newSessions(time.Minute, 100)
	now := time.Now()
	for _, key := range []string{"delta", "alpha", "charlie", "bravo"} {
		s.pin(key, 0, now)
	}

	want := []string{"alpha", "bravo", "charlie", "delta"}
	for range 20 {
		var got []string
		for _, sess := range s.list() {
			got = append(got, sess.Key)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("list() = %v, want %v", got, want)
		}
	}
}
