package stats

import (
	"testing"
	"time"
)

func TestRingBoundsMemory(t *testing.T) {
	// Retention is bounded by the window, not by uptime.
	r := newRing(time.Second, 10*time.Second)
	if len(r.buckets) != 10 {
		t.Fatalf("bucket count = %d, want 10", len(r.buckets))
	}

	now := time.Now().Truncate(time.Second)
	for i := range 100 {
		r.advance(now.Add(time.Duration(i)*time.Second)).requests++
	}
	if got := len(r.series()); got > 10 {
		t.Errorf("series length = %d, want at most 10", got)
	}
}

func TestRingSeriesIsOldestFirst(t *testing.T) {
	r := newRing(time.Second, 5*time.Second)
	now := time.Now().Truncate(time.Second)
	for i := range 3 {
		r.advance(now.Add(time.Duration(i) * time.Second)).requests = int64(i)
	}

	series := r.series()
	if len(series) != 3 {
		t.Fatalf("series length = %d, want 3", len(series))
	}
	for i := 1; i < len(series); i++ {
		if !series[i].At.After(series[i-1].At) {
			t.Errorf("series is not ordered oldest-first: %v then %v", series[i-1].At, series[i].At)
		}
	}
}

func TestRingHandlesLongIdleGap(t *testing.T) {
	// A gap longer than the whole window must not be walked bucket by bucket.
	r := newRing(time.Second, 5*time.Second)
	now := time.Now().Truncate(time.Second)
	r.advance(now).requests = 1

	b := r.advance(now.Add(time.Hour))
	b.requests = 2

	series := r.series()
	if len(series) != 1 {
		t.Fatalf("series length = %d, want 1 — stale buckets should be cleared", len(series))
	}
	if series[0].Requests != 2 {
		t.Errorf("Requests = %d, want 2", series[0].Requests)
	}
}

func TestSameBucketAccumulates(t *testing.T) {
	r := newRing(time.Minute, time.Hour)
	now := time.Now()

	r.advance(now).requests++
	r.advance(now.Add(time.Second)).requests++

	series := r.series()
	if len(series) != 1 {
		t.Fatalf("series length = %d, want 1 — both fall in one bucket", len(series))
	}
	if series[0].Requests != 2 {
		t.Errorf("Requests = %d, want 2", series[0].Requests)
	}
}

func TestPercentiles(t *testing.T) {
	values := []float64{100, 10, 50, 20, 30, 40, 60, 70, 80, 90}
	p50, p95 := percentiles(values)

	if p50 <= 0 || p95 <= 0 {
		t.Fatalf("percentiles = (%v, %v), want positive", p50, p95)
	}
	if p95 < p50 {
		t.Errorf("p95 (%v) must be at least p50 (%v)", p95, p50)
	}
	if p95 != 100 {
		t.Errorf("p95 = %v, want 100", p95)
	}
}

func TestPercentilesEmpty(t *testing.T) {
	p50, p95 := percentiles(nil)
	if p50 != 0 || p95 != 0 {
		t.Errorf("percentiles of nothing = (%v, %v), want (0, 0)", p50, p95)
	}
}

func TestCollectorTotalsAndPerInstance(t *testing.T) {
	c := NewCollector(time.Second, time.Minute)

	c.RecordRequest(1, 100, 900, 50*time.Millisecond, false)
	c.RecordRequest(1, 10, 20, 70*time.Millisecond, true)
	c.RecordRequest(2, 5, 5, 10*time.Millisecond, false)

	totals := c.Totals()
	if totals.Requests != 3 {
		t.Errorf("Requests = %d, want 3", totals.Requests)
	}
	if totals.Failures != 1 {
		t.Errorf("Failures = %d, want 1", totals.Failures)
	}
	if totals.BytesUp != 115 || totals.BytesDown != 925 {
		t.Errorf("bytes = %d/%d, want 115/925", totals.BytesUp, totals.BytesDown)
	}

	one := c.Instance(1)
	if one.Requests != 2 || one.Failures != 1 {
		t.Errorf("instance 1 = %d requests / %d failures, want 2/1", one.Requests, one.Failures)
	}
	// Running mean of 50 and 70.
	if one.LatencyMS < 59 || one.LatencyMS > 61 {
		t.Errorf("instance 1 mean latency = %v, want ~60", one.LatencyMS)
	}
}

func TestCollectorForgetsRetiredInstance(t *testing.T) {
	c := NewCollector(time.Second, time.Minute)
	c.RecordRequest(7, 1, 1, time.Millisecond, false)
	c.Forget(7)

	if got := c.Instance(7).Requests; got != 0 {
		t.Errorf("Requests = %d, want 0 after Forget", got)
	}
}

func TestEventLogIsBounded(t *testing.T) {
	l := NewEventLog(5)
	for i := range 20 {
		l.Add(Event{Type: EventRotate, Message: "rotate", Detail: string(rune('a' + i))})
	}

	events := l.Recent(0)
	if len(events) != 5 {
		t.Fatalf("retained %d events, want 5", len(events))
	}
	// Newest first, and the newest is the last one added.
	if events[0].Seq != 20 {
		t.Errorf("newest Seq = %d, want 20", events[0].Seq)
	}
	if events[len(events)-1].Seq != 16 {
		t.Errorf("oldest retained Seq = %d, want 16", events[len(events)-1].Seq)
	}
}

func TestEventLogRecentLimit(t *testing.T) {
	l := NewEventLog(10)
	for range 6 {
		l.Add(Event{Type: EventRotate, Message: "x"})
	}
	if got := len(l.Recent(3)); got != 3 {
		t.Errorf("Recent(3) returned %d events", got)
	}
	if got := len(l.Recent(100)); got != 6 {
		t.Errorf("Recent(100) returned %d, want the 6 that exist", got)
	}
}

func TestEventLogPartiallyFilled(t *testing.T) {
	l := NewEventLog(10)
	l.Add(Event{Type: EventResize, Message: "one"})
	l.Add(Event{Type: EventResize, Message: "two"})

	events := l.Recent(0)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 — empty slots must not be returned", len(events))
	}
	if events[0].Message != "two" {
		t.Errorf("newest = %q, want two", events[0].Message)
	}
}

func TestEventLogFansOutToSubscribers(t *testing.T) {
	l := NewEventLog(10)
	ch, cancel := l.Subscribe(4)
	defer cancel()

	l.Instance(EventQuarantine, 3, "quarantined", "too many failures")

	select {
	case e := <-ch:
		if e.Type != EventQuarantine {
			t.Errorf("Type = %q, want quarantine", e.Type)
		}
		if e.Instance == nil || *e.Instance != 3 {
			t.Errorf("Instance = %v, want 3", e.Instance)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber received nothing")
	}
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	// A stalled dashboard must never apply backpressure to the pool.
	l := NewEventLog(100)
	_, cancel := l.Subscribe(1) // never drained
	defer cancel()

	done := make(chan struct{})
	go func() {
		for range 50 {
			l.Add(Event{Type: EventRotate, Message: "x"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Add blocked on a subscriber that is not reading")
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	l := NewEventLog(10)
	ch, cancel := l.Subscribe(4)
	cancel()

	l.Add(Event{Type: EventRotate, Message: "after cancel"})

	// The channel is closed, so a receive returns immediately with the zero
	// value rather than the event.
	if e, ok := <-ch; ok && e.Message == "after cancel" {
		t.Error("a cancelled subscriber should not receive further events")
	}
}
