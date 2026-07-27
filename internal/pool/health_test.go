package pool

import (
	"testing"
	"time"
)

func testPolicy() healthPolicy {
	return healthPolicy{
		Window:           time.Minute,
		MaxInWindow:      5,
		MaxConsecutive:   3,
		EscalationWindow: 5 * time.Minute,
		Backoff:          30 * time.Second,
		MaxBackoff:       10 * time.Minute,
	}
}

func TestConsecutiveFailuresQuarantineQuickly(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	// A hard-dead instance must drop out fast, well before the windowed count
	// would trigger.
	for i := 1; i <= p.MaxConsecutive; i++ {
		quarantine := h.recordFailure(SourceTransport, now, p)
		if i < p.MaxConsecutive && quarantine {
			t.Fatalf("quarantined after %d consecutive failures, want %d", i, p.MaxConsecutive)
		}
		if i == p.MaxConsecutive && !quarantine {
			t.Fatalf("should quarantine at %d consecutive failures", p.MaxConsecutive)
		}
	}
	if h.routable(now) {
		t.Error("a quarantined instance must not be routable")
	}
}

func TestInterleavedFailuresStillQuarantine(t *testing.T) {
	// An instance failing half its requests never accumulates consecutive
	// failures, but it is still unhealthy.
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	var quarantined bool
	for range p.MaxInWindow {
		quarantined = h.recordFailure(SourceClient, now, p)
		h.recordSuccess(now, p.Window)
	}
	if !quarantined {
		t.Error("windowed failures should quarantine even when each is followed by a success")
	}
}

func TestFailuresOutsideWindowAreForgotten(t *testing.T) {
	h, p := newHealth(), testPolicy()
	h.markReady()

	old := time.Now()
	for range p.MaxInWindow - 1 {
		h.recordFailure(SourceTransport, old, p)
		h.recordSuccess(old, p.Window)
	}

	// Long after the window, the old failures must not contribute.
	later := old.Add(2 * p.Window)
	if quarantine := h.recordFailure(SourceTransport, later, p); quarantine {
		t.Error("stale failures should have aged out of the window")
	}
}

func TestSuccessResetsConsecutiveButNotWindow(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	h.recordFailure(SourceTransport, now, p)
	h.recordFailure(SourceTransport, now, p)
	h.recordSuccess(now, p.Window)

	view := h.snapshot(now, p.Window)
	if view.ConsecutiveFails != 0 {
		t.Errorf("ConsecutiveFails = %d, want 0 after a success", view.ConsecutiveFails)
	}
	if view.FailuresInWindow != 2 {
		t.Errorf("FailuresInWindow = %d, want 2 — a success does not erase history", view.FailuresInWindow)
	}
}

func TestProbationFailsClosed(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()
	h.remediated(now)

	if h.snapshot(now, p.Window).State != StateProbation {
		t.Fatal("a remediated instance should be on probation")
	}
	// One failure on probation is decisive: the cheap fix demonstrably failed.
	if !h.recordFailure(SourceClient, now, p) {
		t.Error("a single failure on probation should re-quarantine immediately")
	}
}

func TestProbationClearedOnSuccess(t *testing.T) {
	h, now := newHealth(), time.Now()
	h.markReady()
	h.remediated(now)
	h.clearProbation()

	if state := h.snapshot(now, time.Minute).State; state != StateHealthy {
		t.Errorf("state = %q, want healthy after probation is cleared", state)
	}
}

func TestLadderEscalatesOnRecurrence(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	rung, delay := h.nextRung(now, p)
	if rung != RungNewnym || delay != 0 {
		t.Errorf("first remediation = (%v, %s), want (newnym, 0)", rung, delay)
	}

	// Still inside the escalation window: the cheap fix did not hold.
	now = now.Add(time.Minute)
	h.remediated(now)
	if rung, _ := h.nextRung(now, p); rung != RungRestart {
		t.Errorf("second remediation = %v, want restart", rung)
	}

	now = now.Add(time.Minute)
	h.remediated(now)
	rung, delay = h.nextRung(now, p)
	if rung != RungBackoff {
		t.Errorf("third remediation = %v, want backoff_restart", rung)
	}
	if delay <= 0 {
		t.Error("the backoff rung must actually delay")
	}
}

func TestLadderResetsAfterQuietPeriod(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	h.nextRung(now, p)
	h.remediated(now)

	// Far outside the escalation window: this is a fresh problem, so it starts
	// again at the cheapest rung.
	later := now.Add(2 * p.EscalationWindow)
	if rung, _ := h.nextRung(later, p); rung != RungNewnym {
		t.Errorf("rung = %v, want newnym — an old failure should not escalate a new one", rung)
	}
}

func TestBackoffIsCapped(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	var delay time.Duration
	for range 20 {
		h.remediated(now)
		now = now.Add(time.Second)
		_, delay = h.nextRung(now, p)
	}
	if delay > p.MaxBackoff {
		t.Errorf("delay = %s, want at most %s", delay, p.MaxBackoff)
	}
}

func TestBackoffDelayBlocksRouting(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	// Escalate to the backoff rung.
	h.nextRung(now, p)
	h.remediated(now)
	h.nextRung(now, p)
	h.remediated(now)
	_, delay := h.nextRung(now, p)
	h.remediated(now)

	if h.routable(now) {
		t.Error("an instance inside its backoff delay must not take new sessions")
	}
	if !h.routable(now.Add(delay + time.Second)) {
		t.Error("it should become routable once the backoff expires")
	}
}

func TestFailureSourcesAreCountedSeparately(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	h.recordFailure(SourceTransport, now, p)
	h.recordFailure(SourceClient, now, p)
	h.recordFailure(SourceClient, now, p)

	view := h.snapshot(now, p.Window)
	if view.TransportFailures != 1 {
		t.Errorf("TransportFailures = %d, want 1", view.TransportFailures)
	}
	if view.ClientFailures != 2 {
		t.Errorf("ClientFailures = %d, want 2", view.ClientFailures)
	}
}

func TestQuarantineAndRelease(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	h.quarantine(now)
	if h.routable(now) {
		t.Error("an operator-quarantined instance must not be routable")
	}

	h.release()
	if !h.routable(now) {
		t.Error("release should restore routability")
	}
	if view := h.snapshot(now, p.Window); view.FailuresInWindow != 0 {
		t.Errorf("release should clear the failure window, got %d", view.FailuresInWindow)
	}
}

func TestStartingInstanceIsNotRoutable(t *testing.T) {
	h := newHealth()
	if h.routable(time.Now()) {
		t.Error("an instance that has not bootstrapped must not take traffic")
	}
	h.markReady()
	if !h.routable(time.Now()) {
		t.Error("a ready instance should be routable")
	}
}

func TestFailuresDuringRemediationDoNotRequarantine(t *testing.T) {
	// In-flight connections can fail while a restart is under way; those must
	// not stack up extra remediations.
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()
	h.nextRung(now, p)

	for range 10 {
		if h.recordFailure(SourceTransport, now, p) {
			t.Fatal("a failure during remediation should not trigger another quarantine")
		}
	}
}
