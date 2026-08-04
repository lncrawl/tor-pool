package pool

import (
	"testing"
	"time"
)

// ageExit backdates an instance's identity clock, which is what a real pool does
// by simply running for EXIT_TTL.
func ageExit(t *testing.T, p *Pool, instance int, age time.Duration) {
	t.Helper()
	p.healthMu.Lock()
	p.exitSince[instance] = time.Now().Add(-age)
	p.healthMu.Unlock()
}

func TestScheduledRotationStartsTheClockOnFirstSight(t *testing.T) {
	// An instance's identity is aged from when it could carry traffic, not from
	// whenever the pool happened to boot: a candidate seen for the first time is
	// never due on that tick, however long the process has been up.
	p := newTestPool(t)
	p.cfg.ExitTTL = time.Minute

	if _, ok := p.nextScheduledRotation([]int{0}, nil, time.Now()); ok {
		t.Error("an instance seen for the first time must not be due")
	}
	ageExit(t, p, 0, 2*time.Minute)
	if got, ok := p.nextScheduledRotation([]int{0}, nil, time.Now()); !ok || got != 0 {
		t.Errorf("pick = (%d, %v), want instance 0 once its identity outlived the TTL", got, ok)
	}
}

func TestScheduledRotationWaitsForTheSessionsToGo(t *testing.T) {
	// A pinned session is depending on this exit IP whether or not it has a
	// request in flight, so the TTL is a floor on the identity's age and not a
	// schedule.
	p := newTestPool(t)
	p.cfg.ExitTTL = time.Minute
	ageExit(t, p, 0, 2*time.Minute)

	if _, ok := p.nextScheduledRotation([]int{0}, map[int]int{0: 1}, time.Now()); ok {
		t.Error("an instance with a session pinned to it must not be rotated")
	}
	if _, ok := p.nextScheduledRotation([]int{0}, map[int]int{0: 0}, time.Now()); !ok {
		t.Error("the same instance should rotate once nothing is pinned to it")
	}
}

func TestScheduledRotationTakesTheOldestIdentityFirst(t *testing.T) {
	// A queue that built up behind a busy pool drains in the order the identities
	// aged, not by instance number.
	p := newTestPool(t)
	p.cfg.ExitTTL = time.Minute
	ageExit(t, p, 0, 2*time.Minute)
	ageExit(t, p, 1, 9*time.Minute)
	ageExit(t, p, 2, 5*time.Minute)

	if got, _ := p.nextScheduledRotation([]int{0, 1, 2}, nil, time.Now()); got != 1 {
		t.Errorf("pick = %d, want 1, the oldest identity", got)
	}
}

func TestScheduledRotationSkipsARotationInProgress(t *testing.T) {
	// The identity a rotating instance is being judged on is the one it is
	// already replacing, and its grace period covers the rebuild that follows.
	p := newTestPool(t)
	p.cfg.ExitTTL = time.Minute
	ageExit(t, p, 0, 2*time.Minute)

	p.beginRotation(0)
	if _, ok := p.nextScheduledRotation([]int{0}, nil, time.Now()); ok {
		t.Error("an instance already rotating must not be rotated again")
	}

	// endRotation restarts the clock, so the instance leaves the queue outright
	// rather than coming back the moment the grace period lapses.
	p.endRotation(0)
	if _, ok := p.nextScheduledRotation([]int{0}, nil, time.Now()); ok {
		t.Error("a rotation should have restarted the identity clock")
	}
	if pending := p.RotationPending(); pending[0] {
		t.Error("a just-rotated instance must not read as queued")
	}
}

func TestScheduledRotationIsOffWithoutAnExitTTL(t *testing.T) {
	p := newTestPool(t)
	p.cfg.ExitTTL = 0
	ageExit(t, p, 0, 24*time.Hour)

	if _, ok := p.nextScheduledRotation([]int{0}, nil, time.Now()); ok {
		t.Error("EXIT_TTL=0 disables the schedule")
	}
	if pending := p.RotationPending(); pending != nil {
		t.Errorf("pending = %v, want nothing reported when the schedule is off", pending)
	}
}

func TestRotationPendingReportsInstancesHeldUpBySessions(t *testing.T) {
	// The dashboard needs the queued state to explain itself: an aged instance
	// sitting there unrotated is waiting for its sessions, and an operator should
	// not have to infer that.
	p := newTestPool(t)
	p.cfg.ExitTTL = time.Minute
	ageExit(t, p, 0, 2*time.Minute)
	ageExit(t, p, 1, time.Second)

	pending := p.RotationPending()
	if !pending[0] {
		t.Error("instance 0 outlived the TTL and should read as queued")
	}
	if pending[1] {
		t.Error("instance 1 is inside its TTL and must not read as queued")
	}
}

func TestRetiringAnInstanceForgetsItsIdentityClock(t *testing.T) {
	// Indexes are reused, so a stale clock would have whatever takes this index
	// next inherit an identity age it never had.
	p := newTestPool(t)
	p.cfg.ExitTTL = time.Minute
	ageExit(t, p, 0, 2*time.Minute)

	p.forgetInstance(0)
	if _, ok := p.nextScheduledRotation([]int{0}, nil, time.Now()); ok {
		t.Error("a retired instance's clock should have gone with it")
	}
}
