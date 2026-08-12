package pool

import (
	"context"
	"errors"
	"time"

	"github.com/lncrawl/tor-pool/internal/stats"
)

// rotateScheduleInterval is how often the schedule is examined.
//
// Much finer than any useful EXIT_TTL, because age is only half of what decides
// a scheduled rotation: an instance that is due waits for its last session to
// go, and this is how soon after that it rotates. Nothing here touches a control
// port — the tick reads two maps and the session table — so the cadence costs
// nothing.
const rotateScheduleInterval = 15 * time.Second

// runRotationSchedule rotates instances whose exit identity has outlived
// EXIT_TTL, as and when nothing is using them.
//
// Started only when EXIT_TTL is set, and separate from Run's own loop for the
// same reason the exit poll is: this one can end up waiting on the session table
// and the fleet, and the process supervisor must not be held up behind it.
func (p *Pool) runRotationSchedule(ctx context.Context) {
	ticker := time.NewTicker(rotateScheduleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.rotateScheduled()
		}
	}
}

// rotateScheduled rotates one aged, unused instance if there is one.
//
// One per tick, never a batch. Signalling several at once leaves nothing holding
// circuits for a second or two, which is the one state a pool exists to prevent
// — and because instances all start their clocks together at boot, a batch is
// exactly what a naive sweep would do on the first tick after EXIT_TTL.
func (p *Pool) rotateScheduled() {
	if p.sweepRunning() {
		// A pool-wide rotation is already walking the fleet one instance at a
		// time; adding to it would break that guarantee.
		return
	}

	ready := p.readyInstances()
	candidates := make([]int, 0, len(ready))
	for _, inst := range ready {
		candidates = append(candidates, inst.Index())
	}

	instance, ok := p.nextScheduledRotation(candidates, p.sessions.countByInstance(), time.Now())
	if !ok {
		return
	}

	switch err := p.StartRotateInstance(instance); {
	case err == nil:
		p.log.Info("rotating an unused instance whose exit identity reached its TTL",
			"instance", instance, "exit_ttl", p.cfg.ExitTTL)
		p.events.Instance(stats.EventRotate, instance,
			"rotated on schedule: exit identity older than EXIT_TTL", "")
	case errors.Is(err, ErrNoSuchInstance), errors.Is(err, ErrInstanceNotReady):
		// Retired or restarted between the pick and the call. The clock goes with
		// the instance, so there is nothing to reset here.
	default:
		p.log.Warn("scheduled rotation failed", "instance", instance, "error", err)
	}
}

// nextScheduledRotation picks the instance to rotate now — the oldest exit
// identity past EXIT_TTL that no session is pinned to — and reports whether
// there is one.
//
// It also starts the clock for any candidate it has not seen before, which is
// why an instance is never due on the tick it first becomes routable: the
// identity's age is counted from when the instance could carry traffic, so a
// slow bootstrap or a long quarantine is not charged to the exit it ends up with.
//
// A pinned session is what makes an instance "in use", whether or not it has a
// request in flight this instant. Rotating under an idle-but-pinned session
// would change the exit IP of a caller that asked to be sticky and has not
// asked to rotate, which is the promise the whole pool is built around. That
// makes EXIT_TTL a floor on an identity's age and not a period: a busy instance
// rotates when its callers rotate, and SESSION_TTL is what lets an abandoned one
// through.
//
// The session count is a snapshot, so a session pinned in the moment between
// this pick and the signal is diverted by the rotation like any other — the same
// race an operator's rotate button has, and why DRAIN_ON_ROTATE exists.
func (p *Pool) nextScheduledRotation(candidates []int, sessions map[int]int, now time.Time) (int, bool) {
	ttl := p.cfg.ExitTTL
	if ttl <= 0 {
		return 0, false
	}

	p.healthMu.Lock()
	defer p.healthMu.Unlock()

	best, oldest := -1, time.Time{}
	for _, index := range candidates {
		since, seen := p.exitSince[index]
		if !seen {
			p.exitSince[index] = now
			continue
		}
		switch {
		case now.Sub(since) < ttl,
			sessions[index] > 0,
			// Rotating already, or still inside the grace period that follows
			// one: the identity being judged here is the one it is replacing.
			p.rotating[index] > 0,
			now.Before(p.quietUntil[index]):
			continue
		}
		// Oldest first, so a queue that has built up behind a busy pool drains in
		// the order the identities aged rather than by instance number.
		if best < 0 || since.Before(oldest) {
			best, oldest = index, since
		}
	}
	return best, best >= 0
}

// resetExitAge restarts an instance's identity clock, for a caller that has just
// given it a new exit by some route other than a rotation.
//
// A restart is the case: it discards guards and circuits, so the exit that comes
// back is not the one the clock was measuring, and leaving it running would
// rotate a brand-new identity moments after it arrived.
func (p *Pool) resetExitAge(instance int) {
	p.healthMu.Lock()
	p.exitSince[instance] = time.Now()
	p.healthMu.Unlock()
}

// sweepRunning reports whether a pool-wide rotation is in progress.
func (p *Pool) sweepRunning() bool {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	return p.sweeping
}

// RotationPending reports which instances have held their exit identity for
// longer than EXIT_TTL and are waiting only for their sessions to finish.
//
// Reported so an operator is never left wondering why an instance is not
// rotating: the answer is the session count next to it. Empty when EXIT_TTL is
// off, since nothing is then scheduled to happen.
func (p *Pool) RotationPending() map[int]bool {
	ttl := p.cfg.ExitTTL
	if ttl <= 0 {
		return nil
	}
	now := time.Now()

	p.healthMu.Lock()
	defer p.healthMu.Unlock()

	out := make(map[int]bool, len(p.exitSince))
	for index, since := range p.exitSince {
		if now.Sub(since) >= ttl && p.rotating[index] == 0 {
			out[index] = true
		}
	}
	return out
}
