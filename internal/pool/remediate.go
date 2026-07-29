package pool

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lncrawl/tor-pool/internal/stats"
	"github.com/lncrawl/tor-pool/internal/tor"
)

// RecordFailure scores a failure against an instance and starts remediation if
// it has now failed enough.
//
// Both signals land here so one ladder governs them: an instance blocked at the
// HTTP level and an instance whose TCP connections reset are equally unusable,
// and mixing the two counts is deliberate. What is *not* mixed is the kind — a
// captcha and a rate limit are both failures and say opposite things about the
// exit, so the weighing happens in health.recordFailure.
//
// Failures inside an instance's own rotation window are not scored at all. A
// rotation deliberately destroys the circuits in-flight requests were using, so
// those requests fail because of the rotation, not because of the instance —
// blaming it turned every few rotations into a quarantine, whose remediation
// rotated it again.
func (p *Pool) RecordFailure(instance int, source FailureSource, kind FailureKind, reason string) {
	now := time.Now()
	if p.rotationWindow(instance, now) {
		p.log.Debug("failure during rotation is not scored",
			"instance", instance, "source", source, "kind", kind, "reason", reason)
		return
	}

	h := p.healthFor(instance)
	if !h.recordFailure(source, kind, now, p.policy()) {
		return
	}

	p.log.Warn("instance quarantined",
		"instance", instance, "source", source, "kind", kind, "reason", reason)
	p.events.Instance(stats.EventQuarantine, instance,
		"quarantined after repeated failures", failureDetail(source, kind, reason))

	// Sessions are unpinned now rather than when they next ask, so a caller
	// never gets handed an instance already known to be bad.
	if moved := p.sessions.unpinInstance(instance); moved > 0 {
		p.log.Info("sessions moved off quarantined instance",
			"instance", instance, "sessions", moved)
	}

	p.startRemediation(instance)
}

// failureDetail renders a failure for the audit log.
//
// The reason is free text a caller chose, so it may be empty and it may say
// nothing the kind does not already say.
func failureDetail(source FailureSource, kind FailureKind, reason string) string {
	detail := string(source) + " " + string(kind)
	if reason != "" && reason != string(kind) {
		detail += ": " + reason
	}
	return detail
}

// RecordSuccess decays an instance's failure score.
func (p *Pool) RecordSuccess(instance int) {
	h := p.healthFor(instance)
	h.recordSuccess(time.Now(), p.cfg.FailureWindow)
	// Surviving a request is what earns a probationary instance its place back.
	h.clearProbation()
}

// startRemediation launches the ladder for an instance, unless one is already
// running.
func (p *Pool) startRemediation(instance int) {
	p.healthMu.Lock()
	if p.remediating[instance] {
		p.healthMu.Unlock()
		return
	}
	p.remediating[instance] = true
	p.healthMu.Unlock()

	go func() {
		defer func() {
			p.healthMu.Lock()
			delete(p.remediating, instance)
			p.healthMu.Unlock()
		}()
		p.remediate(p.poolCtx(), instance)
	}()
}

// poolCtx returns the context every lifecycle operation runs under.
//
// It is the pool's own lifetime, never a request's. A restart, a resize or a
// NEWNYM outlives the HTTP call that asked for it: tying them to the request
// means the work is cancelled the moment the response is written, which
// silently leaves instances half-started or tor stopped and not restarted.
func (p *Pool) poolCtx() context.Context {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	if p.ctx != nil {
		return p.ctx
	}
	return context.Background()
}

// remediate applies one rung of the ladder to an instance and returns it to
// service on probation.
func (p *Pool) remediate(ctx context.Context, instance int) {
	inst, ok := p.fleet.Get(instance)
	if !ok {
		return
	}

	h := p.healthFor(instance)
	rung, delay := h.nextRung(time.Now(), p.policy())

	log := p.log.With("instance", instance, "rung", rung.String())
	p.events.Instance(stats.EventRemediation, instance,
		"remediating with "+rung.String(), "")
	if delay > 0 {
		log.Warn("instance keeps failing, backing off", "delay", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}

	// Both rungs destroy the circuits any in-flight request is using, so the
	// instance spends the rung inside a rotation window and is not blamed for the
	// failures that follow from it.
	p.beginRotation(instance)
	previousExit := inst.ExitNode().Fingerprint

	var err error
	switch rung {
	case RungNewnym:
		// Cheap and enough when only the exit IP was blocked. Waits out tor's
		// cooldown internally.
		log.Info("requesting a new circuit")
		if p.cfg.PinExitRelay {
			err = inst.UnpinExit(ctx, previousExit)
		}
		if err == nil {
			err = inst.Newnym(ctx)
		}
	case RungRestart, RungBackoff:
		// A wipe discards guards and cached consensus, which is the difference
		// between a new exit and a genuinely new identity.
		log.Warn("restarting tor with wiped state")
		err = inst.Restart(ctx, true)
	}
	p.endRotation(instance)

	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		log.Error("remediation failed", "error", err)
		// Leave it quarantined; the next failure or operator action escalates.
		return
	}

	// The exit relay is stale after either rung, and tor needs a moment to build
	// the circuit that replaces it.
	p.settleExit(ctx, inst)

	h.remediated(time.Now())
	log.Info("instance back in service on probation")
	p.events.Instance(stats.EventRemediation, instance,
		"back in service on probation after "+rung.String(), "")
}

// superviseProcesses recovers the two ways an instance drops out of the pool
// without anything else noticing.
//
// A crashed or OOM-killed tor is reaped and then simply sits there, unroutable,
// silently shrinking the pool. A tor that stalls part-way through bootstrap is
// worse: the process is alive, so nothing looks wrong, and it never becomes ready.
// The failure ladder catches neither, because an instance that takes no traffic
// records no failures.
func (p *Pool) superviseProcesses(ctx context.Context) {
	now := time.Now()
	for _, inst := range p.fleet.Instances() {
		var reason string
		switch {
		case inst.Running() && inst.Ready():
			continue
		case !inst.Running() && !inst.Starting():
			reason = "tor process died"
		case p.bootstrapStalled(inst, now):
			pct, _ := inst.BootstrapProgress()
			reason = fmt.Sprintf("bootstrap stalled at %d%%", pct)
		default:
			// Starting normally, or already being restarted.
			continue
		}

		p.restartUnhealthy(ctx, inst, reason)
	}
}

// bootstrapStalled reports whether an instance has stopped making progress
// towards being usable.
func (p *Pool) bootstrapStalled(inst *tor.Instance, now time.Time) bool {
	timeout := p.cfg.BootstrapStallTimeout
	if timeout <= 0 {
		return false
	}
	pct, since := inst.BootstrapProgress()
	if pct >= 100 || since.IsZero() {
		return false
	}
	return now.Sub(since) > timeout
}

// restartUnhealthy relaunches an instance in the background, wiping its state
// only once keeping it has already been tried.
func (p *Pool) restartUnhealthy(ctx context.Context, inst *tor.Instance, reason string) {
	index := inst.Index()

	p.healthMu.Lock()
	if p.remediating[index] {
		// A restart is already under way; the process is down on purpose.
		p.healthMu.Unlock()
		return
	}
	p.remediating[index] = true
	p.startAttempts[index]++
	attempt := p.startAttempts[index]
	p.healthMu.Unlock()

	// The first attempt keeps the state directory: the process died unexpectedly
	// rather than being judged bad, so its guards and cached consensus are still
	// worth reusing for a faster restart. Once that has failed, they are the most
	// likely thing wrong with it — a stalled bootstrap is usually a poisoned
	// cached consensus.
	wipe := attempt > 1

	p.log.Warn("restarting instance", "instance", index, "reason", reason,
		"attempt", attempt, "wiped", wipe)
	p.events.Instance(stats.EventInstance, index, reason+", restarting", detailForWipe(wipe))
	p.healthFor(index).markStarting()
	p.sessions.unpinInstance(index)

	go func() {
		defer func() {
			p.healthMu.Lock()
			delete(p.remediating, index)
			p.healthMu.Unlock()
		}()

		if err := inst.Restart(ctx, wipe); err != nil {
			if !errors.Is(err, context.Canceled) {
				p.log.Error("restart failed", "instance", index, "error", err)
			}
			return
		}

		p.healthMu.Lock()
		delete(p.startAttempts, index)
		p.healthMu.Unlock()

		p.healthFor(index).release()
		p.log.Info("instance restarted", "instance", index, "reason", reason)
	}()
}

func detailForWipe(wipe bool) string {
	if wipe {
		return "state wiped"
	}
	return "state kept"
}

// QuarantineInstance takes an instance out of rotation on request.
func (p *Pool) QuarantineInstance(instance int) bool {
	if _, ok := p.fleet.Get(instance); !ok {
		return false
	}
	p.healthFor(instance).quarantine(time.Now())
	moved := p.sessions.unpinInstance(instance)
	p.log.Info("instance quarantined by request", "instance", instance, "sessions_moved", moved)
	p.events.Instance(stats.EventQuarantine, instance, "quarantined by request", "")
	return true
}

// ReleaseInstance clears a quarantine and its accumulated failures.
func (p *Pool) ReleaseInstance(instance int) bool {
	if _, ok := p.fleet.Get(instance); !ok {
		return false
	}
	p.healthFor(instance).release()
	p.log.Info("instance released", "instance", instance)
	p.events.Instance(stats.EventQuarantine, instance, "released back into rotation", "")
	return true
}

// RotateInstance asks an instance for a fresh circuit and waits for it.
//
// Takes no context: NEWNYM waits out tor's cooldown, which can outlast the
// request that asked for it. Callers on a request path want StartRotateInstance.
func (p *Pool) RotateInstance(instance int) error {
	inst, err := p.quiesceForRotation(instance)
	if err != nil {
		if errors.Is(err, errRotationInProgress) {
			return nil
		}
		return err
	}
	defer p.endRotation(instance)
	return p.finishRotation(p.poolCtx(), inst)
}

// StartRotateInstance takes an instance out of service for rotation and returns
// as soon as it has, finishing in the background.
//
// The part callers care about is immediate: the instance stops taking new
// sessions and its current ones move away. What is left is tor's NEWNYM cooldown
// — up to ten seconds it will not shorten and cannot be asked about — and there
// is nothing to be gained by holding an HTTP request open for it.
func (p *Pool) StartRotateInstance(instance int) error {
	inst, err := p.quiesceForRotation(instance)
	if err != nil {
		if errors.Is(err, errRotationInProgress) {
			// Someone is already doing exactly this. Reporting success is honest:
			// the instance is rotating.
			return nil
		}
		return err
	}

	go func() {
		defer p.endRotation(instance)
		if err := p.finishRotation(p.poolCtx(), inst); err != nil &&
			!errors.Is(err, context.Canceled) {
			p.log.Warn("rotation failed", "instance", instance, "error", err)
		}
	}()
	return nil
}

// errRotationInProgress means another rotation already owns this instance.
var errRotationInProgress = errors.New("rotation already in progress")

// quiesceForRotation marks an instance as rotating and moves its sessions off.
//
// Order matters. The mark goes up first so nothing new is pinned here while the
// circuits are gone, then the sitting sessions are moved off, and only then does
// the instance lose its circuits. Rotating first would fail the requests that
// arrive in between.
func (p *Pool) quiesceForRotation(instance int) (*tor.Instance, error) {
	inst, ok := p.fleet.Get(instance)
	if !ok {
		return nil, ErrNoSuchInstance
	}
	if !inst.Ready() {
		// Signalling a tor that has no circuits changes nothing and still spends
		// the cooldown, so the rotation asked for once it is ready would be
		// coalesced away.
		return nil, ErrInstanceNotReady
	}
	if !p.beginRotationExclusive(instance) {
		return nil, errRotationInProgress
	}

	if p.cfg.DrainOnRotate {
		if moved := p.divertSessions(instance); moved > 0 {
			p.log.Info("sessions diverted off rotating instance",
				"instance", instance, "sessions_moved", moved)
		}
	}
	return inst, nil
}

// finishRotation does the slow half: retire the circuits and settle on the exit
// that replaces them.
func (p *Pool) finishRotation(ctx context.Context, inst *tor.Instance) error {
	previousExit := inst.ExitNode().Fingerprint
	if p.cfg.PinExitRelay {
		// Tor cannot choose a new exit while it is pinned to the old one, and
		// keeping it out of the running is what stops a rotation from handing
		// back the relay the caller just declared burnt.
		if err := inst.UnpinExit(ctx, previousExit); err != nil {
			return fmt.Errorf("releasing the exit pin: %w", err)
		}
	}
	if err := inst.Newnym(ctx); err != nil {
		return err
	}
	p.settleExit(ctx, inst)
	return nil
}

// settleExit waits for the circuit that replaces the retired one and, when
// pinning is on, locks the instance to its exit.
func (p *Pool) settleExit(ctx context.Context, inst *tor.Instance) {
	node, err := inst.AwaitExitNode(ctx, exitSettleTimeout)
	if err != nil {
		p.log.Debug("exit node not resolvable yet after rotate",
			"instance", inst.Index(), "error", err)
		return
	}
	if !p.cfg.PinExitRelay || node.Fingerprint == "" {
		return
	}
	if err := inst.PinExit(ctx, node.Fingerprint); err != nil {
		p.log.Warn("pinning the exit relay failed",
			"instance", inst.Index(), "error", err)
	}
}

// RestartInstance restarts an instance's tor process, optionally wiping its
// state for a completely new identity.
func (p *Pool) RestartInstance(instance int, wipe bool) error {
	inst, ok := p.fleet.Get(instance)
	if !ok {
		return ErrNoSuchInstance
	}

	h := p.healthFor(instance)
	h.markStarting()
	p.sessions.unpinInstance(instance)

	if err := inst.Restart(p.poolCtx(), wipe); err != nil {
		return err
	}
	h.release()
	p.log.Info("instance restarted", "instance", instance, "wiped", wipe)
	detail := "state kept"
	if wipe {
		detail = "state wiped"
	}
	p.events.Instance(stats.EventRestart, instance, "restarted by request", detail)
	return nil
}

// RotateAll asks every instance for a new circuit, one at a time, and returns
// straight away.
//
// Serial rather than concurrent. Rotating the whole pool at once left every
// instance without circuits for the same second or two, so there was nothing to
// route to and requests failed — the opposite of what a pool is for. One at a
// time the rest keep serving throughout; the sweep takes roughly tor's NEWNYM
// cooldown per instance.
//
// It reports how many instances the sweep will cover, and whether one was
// already running — in which case nothing new is started.
func (p *Pool) RotateAll() (queued int, alreadyRunning bool) {
	instances := p.fleet.Instances()

	p.healthMu.Lock()
	if p.sweeping {
		p.healthMu.Unlock()
		return 0, true
	}
	p.sweeping = true
	p.healthMu.Unlock()

	ctx := p.poolCtx()
	go func() {
		defer func() {
			p.healthMu.Lock()
			p.sweeping = false
			p.healthMu.Unlock()
		}()

		for _, inst := range instances {
			if ctx.Err() != nil {
				return
			}
			index := inst.Index()
			switch err := p.RotateInstance(index); {
			case err == nil,
				errors.Is(err, context.Canceled),
				// Retired mid-sweep, or not bootstrapped yet: neither is worth
				// reporting as a failed rotation.
				errors.Is(err, ErrNoSuchInstance),
				errors.Is(err, ErrInstanceNotReady):
			default:
				p.log.Warn("rotate failed", "instance", index, "error", err)
			}
		}
		p.log.Info("pool-wide rotation finished", "instances", len(instances))
	}()
	return len(instances), false
}

// Resize grows or shrinks the pool at runtime.
//
// Shrinking retires the highest-numbered instances and unpins their sessions, so
// callers move rather than fail.
func (p *Pool) Resize(size int) error {
	// The same bounds boot validation applies. A size the port layout cannot
	// accommodate is not a big pool, it is thousands of tor processes that all
	// fail to bind — asking for one used to take the whole pool down.
	if err := p.cfg.ValidatePoolSize(size); err != nil {
		return err
	}

	// New instances take tens of seconds to bootstrap, far longer than the
	// request that asked for them.
	ctx := p.poolCtx()
	current := p.fleet.Size()
	switch {
	case size > current:
		for n := range size - current {
			if n > 0 && p.cfg.SpawnStagger > 0 {
				// The same reason boot staggers: N simultaneous consensus
				// fetches compete for the same CPU and sockets, and the ones
				// that lose stall part-way through bootstrap.
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(p.cfg.SpawnStagger):
				}
			}
			if _, err := p.fleet.Add(ctx, nil); err != nil {
				return err
			}
		}
		p.log.Info("pool grown", "from", current, "to", size)
		p.events.Add(stats.Event{Type: stats.EventResize,
			Message: fmt.Sprintf("pool grown from %d to %d", current, size)})

	case size < current:
		instances := p.fleet.Instances()
		for _, inst := range instances[size:] {
			index := inst.Index()
			p.sessions.unpinInstance(index)
			if err := p.fleet.Remove(index); err != nil {
				return err
			}
			p.forgetInstance(index)
		}
		p.log.Info("pool shrunk", "from", current, "to", size)
		p.events.Add(stats.Event{Type: stats.EventResize,
			Message: fmt.Sprintf("pool shrunk from %d to %d", current, size)})
	}
	return nil
}
