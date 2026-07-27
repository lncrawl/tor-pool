package pool

import (
	"context"
	"errors"
	"time"

	"github.com/lncrawl/tor-pool/internal/tor"
)

// RecordFailure scores a failure against an instance and starts remediation if
// it has now failed enough.
//
// Both signals land here so one ladder governs them: an instance blocked at the
// HTTP level and an instance whose TCP connections reset are equally unusable,
// and mixing the two counts is deliberate.
func (p *Pool) RecordFailure(instance int, source FailureSource, reason string) {
	h := p.healthFor(instance)
	if !h.recordFailure(source, time.Now(), p.policy()) {
		return
	}

	p.log.Warn("instance quarantined",
		"instance", instance, "source", source, "reason", reason)

	// Sessions are unpinned now rather than when they next ask, so a caller
	// never gets handed an instance already known to be bad.
	if moved := p.sessions.unpinInstance(instance); moved > 0 {
		p.log.Info("sessions moved off quarantined instance",
			"instance", instance, "sessions", moved)
	}

	p.startRemediation(instance)
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
		p.remediate(p.remediationCtx(), instance)
	}()
}

// remediationCtx returns the context remediation runs under.
//
// It is the pool's own lifetime, not a request's: a restart must not be
// abandoned halfway because the client that triggered it went away.
func (p *Pool) remediationCtx() context.Context {
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
	if delay > 0 {
		log.Warn("instance keeps failing, backing off", "delay", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}

	var err error
	switch rung {
	case RungNewnym:
		// Cheap and enough when only the exit IP was blocked. Waits out tor's
		// cooldown internally.
		log.Info("requesting a new circuit")
		err = inst.Newnym(ctx)
	case RungRestart, RungBackoff:
		// A wipe discards guards and cached consensus, which is the difference
		// between a new exit and a genuinely new identity.
		log.Warn("restarting tor with wiped state")
		err = inst.Restart(ctx, true)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		log.Error("remediation failed", "error", err)
		// Leave it quarantined; the next failure or operator action escalates.
		return
	}

	// The exit relay is stale after either rung.
	if _, err := inst.RefreshExitNode(); err != nil {
		log.Debug("exit node not resolvable after remediation", "error", err)
	}

	h.remediated(time.Now())
	log.Info("instance back in service on probation")
}

// superviseProcesses restarts tor processes that have died on their own.
//
// Nothing else will: a crashed or OOM-killed tor is reaped and then simply sits
// there, unroutable, silently shrinking the pool. The failure ladder never
// notices because a dead instance takes no traffic and therefore records no
// failures.
func (p *Pool) superviseProcesses(ctx context.Context) {
	for _, inst := range p.fleet.Instances() {
		index := inst.Index()
		if inst.Running() {
			continue
		}

		p.healthMu.Lock()
		busy := p.remediating[index]
		if !busy {
			p.remediating[index] = true
		}
		p.healthMu.Unlock()
		if busy {
			// A restart is already under way; the process is down on purpose.
			continue
		}

		p.log.Warn("tor process died, restarting", "instance", index)
		p.healthFor(index).markStarting()
		p.sessions.unpinInstance(index)

		go func(inst *tor.Instance, index int) {
			defer func() {
				p.healthMu.Lock()
				delete(p.remediating, index)
				p.healthMu.Unlock()
			}()

			// Keep the state directory: the process died unexpectedly rather
			// than being judged bad, so its guards and cached consensus are
			// still worth reusing for a faster restart.
			if err := inst.Restart(ctx, false); err != nil {
				if !errors.Is(err, context.Canceled) {
					p.log.Error("restart after crash failed", "instance", index, "error", err)
				}
				return
			}
			p.healthFor(index).release()
			p.log.Info("instance restarted after crash", "instance", index)
		}(inst, index)
	}
}

// QuarantineInstance takes an instance out of rotation on request.
func (p *Pool) QuarantineInstance(instance int) bool {
	if _, ok := p.fleet.Get(instance); !ok {
		return false
	}
	p.healthFor(instance).quarantine(time.Now())
	moved := p.sessions.unpinInstance(instance)
	p.log.Info("instance quarantined by request", "instance", instance, "sessions_moved", moved)
	return true
}

// ReleaseInstance clears a quarantine and its accumulated failures.
func (p *Pool) ReleaseInstance(instance int) bool {
	if _, ok := p.fleet.Get(instance); !ok {
		return false
	}
	p.healthFor(instance).release()
	p.log.Info("instance released", "instance", instance)
	return true
}

// RotateInstance asks an instance for a fresh circuit.
func (p *Pool) RotateInstance(ctx context.Context, instance int) error {
	inst, ok := p.fleet.Get(instance)
	if !ok {
		return errors.New("no such instance")
	}
	if err := inst.Newnym(ctx); err != nil {
		return err
	}
	if _, err := inst.RefreshExitNode(); err != nil {
		p.log.Debug("exit node not resolvable after rotate", "instance", instance, "error", err)
	}
	return nil
}

// RestartInstance restarts an instance's tor process, optionally wiping its
// state for a completely new identity.
func (p *Pool) RestartInstance(ctx context.Context, instance int, wipe bool) error {
	inst, ok := p.fleet.Get(instance)
	if !ok {
		return errors.New("no such instance")
	}

	h := p.healthFor(instance)
	h.markStarting()
	p.sessions.unpinInstance(instance)

	if err := inst.Restart(ctx, wipe); err != nil {
		return err
	}
	h.release()
	p.log.Info("instance restarted", "instance", instance, "wiped", wipe)
	return nil
}

// RotateAll asks every instance for a new circuit.
//
// Instances rotate concurrently but each waits out its own NEWNYM cooldown, so
// this can take up to that cooldown to finish.
func (p *Pool) RotateAll(ctx context.Context) int {
	instances := p.fleet.Instances()
	for _, inst := range instances {
		go func(index int) {
			if err := p.RotateInstance(ctx, index); err != nil && !errors.Is(err, context.Canceled) {
				p.log.Warn("rotate failed", "instance", index, "error", err)
			}
		}(inst.Index())
	}
	return len(instances)
}

// Resize grows or shrinks the pool at runtime.
//
// Shrinking retires the highest-numbered instances and unpins their sessions, so
// callers move rather than fail.
func (p *Pool) Resize(ctx context.Context, size int) error {
	if size < 1 {
		return errors.New("pool size must be at least 1")
	}

	current := p.fleet.Size()
	switch {
	case size > current:
		for range size - current {
			if _, err := p.fleet.Add(ctx, nil); err != nil {
				return err
			}
		}
		p.log.Info("pool grown", "from", current, "to", size)

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
	}
	return nil
}
