package stats

import (
	"testing"
	"time"
)

func TestSkippedBucketsGetTheirOwnTimestamp(t *testing.T) {
	// Stamping every skipped bucket with the newest instant collapses them
	// onto one x position and the chart draws a vertical wall.
	r := newRing(time.Second, 60*time.Second)
	now := time.Now().Truncate(time.Second)

	r.advance(now)
	r.advance(now.Add(4 * time.Second))

	series := r.series()
	if len(series) != 5 {
		t.Fatalf("series length = %d, want 5 (one per second)", len(series))
	}
	for i := 1; i < len(series); i++ {
		gap := series[i].At.Sub(series[i-1].At)
		if gap != time.Second {
			t.Errorf("gap between bucket %d and %d = %s, want 1s", i-1, i, gap)
		}
	}
}

func TestGaugeCarriesIntoSkippedBuckets(t *testing.T) {
	// routable is a gauge. A quiet second means "unchanged", not "zero
	// instances were routable" — reading it as zero drew a sawtooth.
	r := newRing(time.Second, 60*time.Second)
	now := time.Now().Truncate(time.Second)

	r.advance(now).routable = 3
	r.advance(now.Add(5 * time.Second))

	for _, s := range r.series() {
		if s.Routable != 3 {
			t.Errorf("bucket at %s has Routable = %d, want 3 carried forward",
				s.At.Format("05.000"), s.Routable)
		}
	}
}

func TestGaugeCarriesAcrossAFullWrap(t *testing.T) {
	r := newRing(time.Second, 3*time.Second)
	now := time.Now().Truncate(time.Second)

	r.advance(now).routable = 2
	// Far enough ahead to clear the whole ring.
	r.advance(now.Add(time.Hour))

	series := r.series()
	if len(series) != 1 {
		t.Fatalf("series length = %d, want 1", len(series))
	}
	if series[0].Routable != 2 {
		t.Errorf("Routable = %d, want 2 carried across the wrap", series[0].Routable)
	}
}

func TestCountersDoNotCarry(t *testing.T) {
	// The opposite of the gauge rule: requests are per-bucket and a quiet
	// second genuinely had none.
	r := newRing(time.Second, 60*time.Second)
	now := time.Now().Truncate(time.Second)

	r.advance(now).requests = 7
	r.advance(now.Add(3 * time.Second))

	series := r.series()
	if series[0].Requests != 7 {
		t.Errorf("first bucket Requests = %d, want 7", series[0].Requests)
	}
	for _, s := range series[1:] {
		if s.Requests != 0 {
			t.Errorf("quiet bucket has Requests = %d, want 0", s.Requests)
		}
	}
}
