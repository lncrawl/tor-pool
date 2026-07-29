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
		quarantine := h.recordFailure(SourceTransport, KindTransport, now, p)
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
		quarantined = h.recordFailure(SourceClient, KindOther, now, p)
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
		h.recordFailure(SourceTransport, KindTransport, old, p)
		h.recordSuccess(old, p.Window)
	}

	// Long after the window, the old failures must not contribute.
	later := old.Add(2 * p.Window)
	if quarantine := h.recordFailure(SourceTransport, KindTransport, later, p); quarantine {
		t.Error("stale failures should have aged out of the window")
	}
}

func TestSuccessResetsConsecutiveButNotWindow(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	h.recordFailure(SourceTransport, KindTransport, now, p)
	h.recordFailure(SourceTransport, KindTransport, now, p)
	h.recordSuccess(now, p.Window)

	view := h.snapshot(now, p)
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

	if h.snapshot(now, p).State != StateProbation {
		t.Fatal("a remediated instance should be on probation")
	}
	// One failure on probation is decisive: the cheap fix demonstrably failed.
	if !h.recordFailure(SourceClient, KindOther, now, p) {
		t.Error("a single failure on probation should re-quarantine immediately")
	}
}

func TestProbationClearedOnSuccess(t *testing.T) {
	h, now := newHealth(), time.Now()
	h.markReady()
	h.remediated(now)
	h.clearProbation()

	if state := h.snapshot(now, testPolicy()).State; state != StateHealthy {
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

	h.recordFailure(SourceTransport, KindTransport, now, p)
	h.recordFailure(SourceClient, KindOther, now, p)
	h.recordFailure(SourceClient, KindOther, now, p)

	view := h.snapshot(now, p)
	if view.TransportFailures != 1 {
		t.Errorf("TransportFailures = %d, want 1", view.TransportFailures)
	}
	if view.ClientFailures != 2 {
		t.Errorf("ClientFailures = %d, want 2", view.ClientFailures)
	}
}

func TestUnclassifiedFailuresCountAsWholeReports(t *testing.T) {
	// The compatibility guarantee behind the weighting: QUARANTINE_FAILURES still
	// means that many failures when nothing is known about them, which is what a
	// bodyless report — the documented minimum signal — produces.
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	for i := 1; i <= p.MaxInWindow; i++ {
		quarantine := h.recordFailure(SourceClient, KindOther, now, p)
		h.recordSuccess(now, p.Window)
		switch {
		case i < p.MaxInWindow && quarantine:
			t.Fatalf("quarantined after %d unclassified failures, want %d", i, p.MaxInWindow)
		case i == p.MaxInWindow && !quarantine:
			t.Fatalf("should quarantine at %d unclassified failures", p.MaxInWindow)
		}
	}
}

func TestWeightsHoldAtEveryThreshold(t *testing.T) {
	// The weights are relative to QUARANTINE_FAILURES, and operations.md tells
	// operators to lower it — so the promises have to survive that, not just hold
	// at the default. Without the ceiling in weight() a captcha *is* the whole
	// threshold at 3, and one caller misreading one page retires an instance.
	//
	// Every report here has a success after it, which resets the consecutive count
	// and leaves the weighted window as the only thing that can quarantine.
	reports := func(t *testing.T, threshold int, kind FailureKind) int {
		t.Helper()
		p := testPolicy()
		p.MaxInWindow = threshold
		h, now := newHealth(), time.Now()
		h.markReady()

		for i := 1; i <= 4*threshold; i++ {
			if h.recordFailure(SourceClient, kind, now, p) {
				return i
			}
			h.recordSuccess(now, p.Window)
		}
		t.Fatalf("QUARANTINE_FAILURES=%d: %q never quarantined", threshold, kind)
		return 0
	}

	for threshold := 1; threshold <= 6; threshold++ {
		// The compatibility promise: the threshold is that many untyped failures,
		// whatever it is set to.
		if got := reports(t, threshold, KindOther); got != threshold {
			t.Errorf("QUARANTINE_FAILURES=%d: %d unclassified failures quarantined, want %d",
				threshold, got, threshold)
		}

		// A single report is never enough on its own — a caller can misread one
		// page — unless the operator set the threshold to one report exactly.
		want := 2
		if threshold == 1 {
			want = 1
		}
		if got := reports(t, threshold, KindCaptcha); got < want {
			t.Errorf("QUARANTINE_FAILURES=%d: %d captcha(s) quarantined, want at least %d",
				threshold, got, want)
		}

		// And the ordering holds throughout: heavier evidence never needs more
		// reports than lighter evidence.
		captcha, blocked := reports(t, threshold, KindCaptcha), reports(t, threshold, KindBlocked)
		limited := reports(t, threshold, KindRateLimited)
		if captcha > blocked || blocked > threshold || threshold > limited {
			t.Errorf("QUARANTINE_FAILURES=%d: reports to quarantine were captcha %d, blocked %d, untyped %d, rate limited %d — want ascending",
				threshold, captcha, blocked, threshold, limited)
		}
	}
}

func TestCaptchaQuarantinesWellBeforeTheReportThreshold(t *testing.T) {
	// A captcha says the exit IP itself is burnt. Waiting for QUARANTINE_FAILURES
	// of them means four more requests answered with a challenge.
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	if h.recordFailure(SourceClient, KindCaptcha, now, p) {
		t.Error("one captcha should not quarantine: a caller can misread a page")
	}
	if !h.recordFailure(SourceClient, KindCaptcha, now, p) {
		t.Fatal("a second captcha should quarantine, well before QUARANTINE_FAILURES")
	}
	if view := h.snapshot(now, p); view.FailuresInWindow >= p.MaxInWindow {
		t.Errorf("FailuresInWindow = %d, want fewer than the %d reports a threshold in counts would need",
			view.FailuresInWindow, p.MaxInWindow)
	}
}

func TestBlockedIsWeighedAboveAnUnexplainedFailure(t *testing.T) {
	// A 403 is the destination refusing this exit — not broken, unwelcome, and
	// retrying never makes it welcome. Still lighter than a captcha, because a
	// 403 can be about the path rather than the IP.
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	h.recordFailure(SourceClient, KindBlocked, now, p)
	h.recordSuccess(now, p.Window)
	if quarantine := h.recordFailure(SourceClient, KindBlocked, now, p); quarantine {
		t.Error("two blocks should not quarantine yet")
	}
	h.recordSuccess(now, p.Window)
	if !h.recordFailure(SourceClient, KindBlocked, now, p) {
		t.Error("three blocks should quarantine, sooner than three unexplained failures would")
	}
}

func TestRateLimitedDoesNotSpendAWorkingExit(t *testing.T) {
	// A 429 says the exit answered and is being asked for too much. Rotating away
	// from it discards a working exit and takes the rate limit to the next one.
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	for i := range p.MaxInWindow {
		if h.recordFailure(SourceClient, KindRateLimited, now, p) {
			t.Fatalf("quarantined after %d rate limits, which say nothing about the exit", i+1)
		}
	}
	if view := h.snapshot(now, p); view.ConsecutiveFails != 0 {
		t.Errorf("ConsecutiveFails = %d, want 0 — a rate limit must not trip the consecutive count",
			view.ConsecutiveFails)
	}

	// Not free, though: sustained throttling is worth moving away from, because a
	// fresh exit IP does reset a per-IP bucket.
	var quarantined bool
	for range 2 * p.MaxInWindow {
		if h.recordFailure(SourceClient, KindRateLimited, now, p) {
			quarantined = true
			break
		}
	}
	if !quarantined {
		t.Error("relentless rate limiting should eventually move the instance")
	}
}

func TestRateLimitedDoesNotEndProbation(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()
	h.remediated(now)

	if h.recordFailure(SourceClient, KindRateLimited, now, p) {
		t.Error("a rate limit is not evidence that a remediation failed")
	}
	if state := h.snapshot(now, p).State; state != StateProbation {
		t.Fatalf("state = %q, want probation — a rate limit must not spend it", state)
	}
	// The probation is still armed for a report that does blame the exit.
	if !h.recordFailure(SourceClient, KindCaptcha, now, p) {
		t.Error("a captcha on probation should re-quarantine immediately")
	}
}

func TestFailureKindsAreCountedAndScored(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	h.recordFailure(SourceClient, KindCaptcha, now, p)
	h.recordFailure(SourceClient, KindRateLimited, now, p)
	h.recordFailure(SourceTransport, KindTransport, now, p)

	view := h.snapshot(now, p)
	for kind, want := range map[FailureKind]int64{
		KindCaptcha: 1, KindRateLimited: 1, KindTransport: 1, KindBlocked: 0,
	} {
		if got := view.FailuresByKind[kind]; got != want {
			t.Errorf("FailuresByKind[%q] = %d, want %d", kind, got, want)
		}
	}
	if view.FailuresInWindow != 3 {
		t.Errorf("FailuresInWindow = %d, want 3", view.FailuresInWindow)
	}
	// A score without its threshold is unreadable, so both are reported.
	if view.FailureScore <= view.FailuresInWindow {
		t.Errorf("FailureScore = %d, want more than the %d reports — a captcha weighs more than one",
			view.FailureScore, view.FailuresInWindow)
	}
	if view.QuarantineScore != p.quarantineScore() {
		t.Errorf("QuarantineScore = %d, want %d", view.QuarantineScore, p.quarantineScore())
	}
}

func TestAgedOutFailuresGiveBackTheirWeight(t *testing.T) {
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.markReady()

	h.recordFailure(SourceClient, KindCaptcha, now, p)
	later := now.Add(2 * p.Window)
	if score := h.snapshot(later, p).FailureScore; score != 0 {
		t.Errorf("FailureScore = %d, want 0 once the window has passed", score)
	}
}

func TestParseFailureKind(t *testing.T) {
	// The aliases are the compatibility surface: these are the strings scraper
	// has always sent, and they have to keep weighing what they mean.
	for text, want := range map[string]FailureKind{
		"captcha":      KindCaptcha,
		"challenge":    KindCaptcha,
		"http_403":     KindBlocked,
		"403":          KindBlocked,
		"http_429":     KindRateLimited,
		"Rate_Limited": KindRateLimited,
		"  transport ": KindTransport,
		"other":        KindOther,
	} {
		got, known := ParseFailureKind(text)
		if !known || got != want {
			t.Errorf("ParseFailureKind(%q) = (%q, %v), want (%q, true)", text, got, known, want)
		}
	}

	// Unrecognised text is not an error: the report is still evidence, so it
	// reports the fallback kind and lets the caller decide.
	for _, text := range []string{"", "who knows", "429s galore"} {
		got, known := ParseFailureKind(text)
		if known || got != KindOther {
			t.Errorf("ParseFailureKind(%q) = (%q, %v), want (other, false)", text, got, known)
		}
	}
}

func TestReportedKindDecidesWhenAnInstanceIsQuarantined(t *testing.T) {
	// The whole path a caller's report takes: session → instance → weighted
	// score. Two captchas retire the instance; the same number of rate limits
	// leaves it serving, because the exit was never the problem.
	quarantined := func(t *testing.T, kind FailureKind, reports int) bool {
		t.Helper()
		p := newTestPool(t)
		p.healthFor(0).markReady()
		p.sessions.pin("alice", 0, time.Now())

		for i := range reports {
			if i > 0 {
				// A success in between, as a caller that is still getting work done
				// has. It resets the consecutive count, so what is left to quarantine
				// the instance is the weighted window and nothing else.
				p.RecordSuccess(0)
			}
			if instance, ok := p.ReportFailure("alice", kind, "reported by a test"); !ok || instance != 0 {
				t.Fatalf("ReportFailure = (%d, %v), want (0, true)", instance, ok)
			}
		}
		return p.healthFor(0).snapshot(time.Now(), p.policy()).State == StateQuarantined
	}

	if !quarantined(t, KindCaptcha, 2) {
		t.Error("two captchas should quarantine: the exit IP itself is burnt")
	}
	if quarantined(t, KindRateLimited, 2) {
		t.Error("two rate limits should not quarantine: the exit works and is busy")
	}
	// Read from configuration rather than written as a literal: this is the
	// compatibility promise, so it has to track QUARANTINE_FAILURES itself.
	threshold := newTestPool(t).cfg.QuarantineFailures
	if quarantined(t, KindOther, threshold-1) {
		t.Errorf("%d unclassified failures should not quarantine", threshold-1)
	}
	if !quarantined(t, KindOther, threshold) {
		t.Errorf("%d unclassified failures should quarantine, exactly as before kinds existed", threshold)
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
	if view := h.snapshot(now, p); view.FailuresInWindow != 0 {
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
		if h.recordFailure(SourceTransport, KindTransport, now, p) {
			t.Fatal("a failure during remediation should not trigger another quarantine")
		}
	}
}
