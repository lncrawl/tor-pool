package pool

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/tor"
)

// newTestPool builds a pool over an empty fleet. Nothing here starts a tor
// process; these tests exercise the bookkeeping that decides what happens to
// requests and health around a rotation.
func newTestPool(t *testing.T) *Pool {
	t.Helper()
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(&cfg, tor.NewFleet(tor.FleetOptions{
		SocksPortFor:   cfg.InstanceSocksPort,
		ControlPortFor: cfg.InstanceControlPort,
	}, log), log)
}

func TestFailuresDuringRotationAreNotScored(t *testing.T) {
	// A rotation destroys the circuits in-flight requests were using, so those
	// requests fail because of the rotation. Scoring them quarantined healthy
	// instances, whose remediation rotated them again.
	p := newTestPool(t)
	p.healthFor(0).markReady()

	p.beginRotation(0)
	for range p.cfg.QuarantineConsecutive + 2 {
		p.RecordFailure(0, SourceTransport, "circuit closed by rotation")
	}
	if state := p.healthFor(0).snapshot(time.Now(), p.cfg.FailureWindow).State; state == StateQuarantined {
		t.Errorf("state = %s, want an instance still in service", state)
	}

	// The grace period keeps covering the requests that were already in flight
	// when the rotation finished.
	p.endRotation(0)
	p.RecordFailure(0, SourceTransport, "still draining")
	if got := p.healthFor(0).snapshot(time.Now(), p.cfg.FailureWindow).ConsecutiveFails; got != 0 {
		t.Errorf("consecutive failures = %d, want 0 inside the grace period", got)
	}

	// Once the window has passed, failures count again — a genuinely broken
	// instance must still be caught.
	p.healthMu.Lock()
	p.quietUntil[0] = time.Now().Add(-time.Second)
	p.healthMu.Unlock()
	for range p.cfg.QuarantineConsecutive {
		p.RecordFailure(0, SourceTransport, "genuinely broken")
	}
	if state := p.healthFor(0).snapshot(time.Now(), p.cfg.FailureWindow).State; state != StateQuarantined {
		t.Errorf("state = %s, want quarantined once the grace period is over", state)
	}
}

func TestRotationsDoNotStack(t *testing.T) {
	p := newTestPool(t)

	if !p.beginRotationExclusive(3) {
		t.Fatal("the first rotation should take the mark")
	}
	if p.beginRotationExclusive(3) {
		t.Error("a second rotation must not stack another cooldown wait onto the first")
	}
	if !p.isRotating(3) {
		t.Error("the instance should read as rotating")
	}

	p.endRotation(3)
	if p.isRotating(3) {
		t.Error("the mark should be cleared")
	}
	if !p.rotationWindow(3, time.Now()) {
		t.Error("the grace period should still be running")
	}
	if p.rotationWindow(3, time.Now().Add(2*rotationGrace)) {
		t.Error("the grace period should expire")
	}
}

func TestRotatingAnAbsentInstanceIsRejected(t *testing.T) {
	p := newTestPool(t)

	if err := p.StartRotateInstance(9); !errors.Is(err, ErrNoSuchInstance) {
		t.Errorf("err = %v, want ErrNoSuchInstance", err)
	}
	if err := p.RotateInstance(9); !errors.Is(err, ErrNoSuchInstance) {
		t.Errorf("err = %v, want ErrNoSuchInstance", err)
	}
}

func TestPreferSettledFallsBackWhenEverythingRotates(t *testing.T) {
	// A single-instance pool still has to route, so the preference cannot become
	// a requirement.
	p := newTestPool(t)
	p.beginRotation(0)

	candidates := []*tor.Instance{tor.NewInstance("tor", tor.InstanceConfig{Index: 0},
		slog.New(slog.NewTextHandler(io.Discard, nil)))}
	if got := p.preferSettled(candidates); len(got) != 1 {
		t.Errorf("candidates = %d, want the rotating instance as a last resort", len(got))
	}
}

func TestBackoffGrowsPerRungNotPerLifetime(t *testing.T) {
	// An instance that misbehaved a lot last week must start today's first
	// backoff at the base delay, not at the maximum.
	h, p, now := newHealth(), testPolicy(), time.Now()
	h.remediations = 50

	// Not recurring: the cheapest rung, no delay.
	if rung, delay := h.nextRung(now, p); rung != RungNewnym || delay != 0 {
		t.Fatalf("first remediation = (%s, %s), want (newnym, 0)", rung, delay)
	}
	// Recurring twice more to reach the backoff rung.
	h.nextRung(now.Add(time.Second), p)
	rung, delay := h.nextRung(now.Add(2*time.Second), p)
	if rung != RungBackoff {
		t.Fatalf("rung = %s, want backoff", rung)
	}
	if delay != p.Backoff {
		t.Errorf("delay = %s, want the base backoff %s", delay, p.Backoff)
	}
	// The next one at the same rung doubles.
	if _, delay := h.nextRung(now.Add(3*time.Second), p); delay != 2*p.Backoff {
		t.Errorf("second backoff delay = %s, want %s", delay, 2*p.Backoff)
	}
}
