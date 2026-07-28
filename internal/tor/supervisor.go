package tor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// bootstrapPoll is how often a starting instance's bootstrap progress is read.
const bootstrapPoll = time.Second

// Instance is one supervised tor process together with its control connection.
//
// It owns the lifecycle of both: the process, the authenticated control
// connection, and the state that says whether the pair is usable. Higher layers
// treat it as an opaque backend they can route to, rotate, or restart.
type Instance struct {
	cfg   InstanceConfig
	proc  *Process
	log   *slog.Logger
	binry string

	// ctrlMu serialises control-port commands. The protocol is one synchronous
	// request/reply stream, so two overlapping commands read each other's
	// replies. It is separate from mu because a command may block for a long
	// time — Newnym waits out tor's cooldown — and mu must never be held across
	// that.
	ctrlMu sync.Mutex

	mu        sync.Mutex
	ctrl      *Control
	bootstrap int
	ready     bool
	startedAt time.Time
	exitNode  ExitNode

	// retiredExit is the exit a rotation or restart just discarded. An idle
	// instance builds no replacement circuit until traffic arrives, so this is
	// kept purely so the operator can still see what it *was* — never as the
	// current exit, which is genuinely unknown until the next request.
	retiredExit ExitNode
}

// NewInstance prepares an instance. Nothing runs until Start is called.
func NewInstance(binary string, cfg InstanceConfig, log *slog.Logger) *Instance {
	inst := &Instance{cfg: cfg, log: log.With("instance", cfg.Index), binry: binary}
	inst.proc = NewProcess(binary, cfg, inst.onTorLog)
	return inst
}

// Config returns this instance's static configuration.
func (i *Instance) Config() InstanceConfig { return i.cfg }

// Index is the instance's position in the pool.
func (i *Instance) Index() int { return i.cfg.Index }

// Start launches tor, waits for its control port, and blocks until it has
// bootstrapped. It returns a non-nil error if any of those steps fails.
func (i *Instance) Start(ctx context.Context) error {
	i.mu.Lock()
	i.startedAt = time.Now()
	i.ready = false
	i.bootstrap = 0
	i.mu.Unlock()

	if err := i.proc.Start(ctx); err != nil {
		return fmt.Errorf("instance %d: %w", i.cfg.Index, err)
	}
	i.log.Info("tor started", "pid", i.proc.Pid())

	ctrl, err := Connect(ctx, i.cfg)
	if err != nil {
		return fmt.Errorf("instance %d: %w", i.cfg.Index, err)
	}
	i.mu.Lock()
	i.ctrl = ctrl
	i.mu.Unlock()
	i.log.Debug("control port authenticated")

	err = WaitBootstrapped(ctx, ctrl, bootstrapPoll, func(pct int) {
		i.mu.Lock()
		changed := pct != i.bootstrap
		i.bootstrap = pct
		i.mu.Unlock()
		if changed {
			i.log.Debug("bootstrapping", "percent", pct)
		}
	})
	if err != nil {
		return fmt.Errorf("instance %d: %w", i.cfg.Index, err)
	}

	i.mu.Lock()
	i.ready = true
	i.mu.Unlock()
	i.log.Info("bootstrapped", "took", time.Since(i.startedAt).Round(time.Millisecond))

	return nil
}

// Ready reports whether this instance has bootstrapped and is routable.
func (i *Instance) Ready() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.ready && i.proc.Running()
}

// Bootstrap reports the last known bootstrap percentage.
func (i *Instance) Bootstrap() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.bootstrap
}

// StartedAt reports when the current process was launched.
func (i *Instance) StartedAt() time.Time {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.startedAt
}

// Running reports whether the tor process is alive, regardless of bootstrap.
func (i *Instance) Running() bool { return i.proc.Running() }

// Pid returns the tor process id, or 0 when not running.
func (i *Instance) Pid() int { return i.proc.Pid() }

// Newnym requests a fresh circuit, waiting out tor's cooldown first.
func (i *Instance) Newnym(ctx context.Context) error {
	i.ctrlMu.Lock()
	defer i.ctrlMu.Unlock()

	i.mu.Lock()
	ctrl := i.ctrl
	i.mu.Unlock()
	if ctrl == nil {
		return errors.New("tor: instance has no control connection")
	}
	if err := ctrl.Newnym(ctx); err != nil {
		return fmt.Errorf("instance %d newnym: %w", i.cfg.Index, err)
	}

	// The cached exit is not merely stale now, it is wrong: NEWNYM retired that
	// circuit, so reporting it would name a relay this instance no longer goes
	// out through.
	i.retireExit()

	// NEWNYM leaves the retired circuits standing, and tor builds no replacement
	// while they do. Closing them is what turns a rotation into a new exit on the
	// very next request instead of whenever tor gets round to it.
	closed, err := ctrl.CloseRetiredCircuits()
	if err != nil {
		// The rotation itself succeeded, so this is not worth failing the caller
		// over: the exit is retired either way, just slower to be replaced.
		i.log.Warn("closing retired circuits failed", "closed", closed, "error", err)
	}

	i.log.Info("new circuit requested", "circuits_closed", closed)
	return nil
}

// NewnymWait reports the remaining NEWNYM cooldown for this instance.
func (i *Instance) NewnymWait() time.Duration {
	i.mu.Lock()
	ctrl := i.ctrl
	i.mu.Unlock()
	if ctrl == nil {
		return 0
	}
	return ctrl.NewnymWait()
}

// RefreshExitNode re-reads the current exit relay from the control port and
// caches it.
//
// This is read from tor's consensus view, so it costs no Tor bandwidth. It
// fails harmlessly while no general-purpose circuit exists yet.
func (i *Instance) RefreshExitNode() (ExitNode, error) {
	i.ctrlMu.Lock()
	defer i.ctrlMu.Unlock()

	i.mu.Lock()
	ctrl := i.ctrl
	i.mu.Unlock()
	if ctrl == nil {
		return ExitNode{}, errors.New("tor: instance has no control connection")
	}

	node, err := ctrl.ExitNode()
	if err != nil {
		return ExitNode{}, err
	}
	i.mu.Lock()
	i.exitNode = node
	i.retiredExit = ExitNode{}
	i.mu.Unlock()
	return node, nil
}

// exitRetryInterval is how often AwaitExitNode retries while tor is still
// building the circuit it will report.
const exitRetryInterval = 250 * time.Millisecond

// AwaitExitNode re-reads the exit relay, retrying until tor has a circuit worth
// reporting or timeout elapses.
//
// Callers use this straight after a rotation: NEWNYM leaves the instance with no
// reportable exit at all for a second or two, and waiting it out is the
// difference between answering with the new exit and answering with nothing.
func (i *Instance) AwaitExitNode(ctx context.Context, timeout time.Duration) (ExitNode, error) {
	deadline := time.Now().Add(timeout)

	ticker := time.NewTicker(exitRetryInterval)
	defer ticker.Stop()

	for {
		node, err := i.RefreshExitNode()
		if err == nil {
			return node, nil
		}
		if time.Now().After(deadline) {
			return ExitNode{}, err
		}
		select {
		case <-ctx.Done():
			return ExitNode{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// ExitNode returns the last known exit relay, which may be zero if no circuit
// has been observed yet.
func (i *Instance) ExitNode() ExitNode {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.exitNode
}

// RetiredExit returns the exit a rotation or restart discarded, if the
// replacement is not known yet. It is zero once a current exit is resolved.
func (i *Instance) RetiredExit() ExitNode {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.retiredExit
}

// retireExit moves the current exit aside: it is no longer where this instance
// goes out, and nothing else is either until tor builds a circuit.
func (i *Instance) retireExit() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.exitNode.Address != "" {
		i.retiredExit = i.exitNode
	}
	i.exitNode = ExitNode{}
}

// SetExitPolicy applies exit-node selection at runtime.
func (i *Instance) SetExitPolicy(exitNodes, excludeExitNodes string, strict bool) error {
	i.ctrlMu.Lock()
	defer i.ctrlMu.Unlock()

	i.mu.Lock()
	ctrl := i.ctrl
	i.mu.Unlock()
	if ctrl == nil {
		return errors.New("tor: instance has no control connection")
	}
	for _, kv := range []struct{ key, value string }{
		{"ExitNodes", exitNodes},
		{"ExcludeExitNodes", excludeExitNodes},
	} {
		if err := ctrl.SetConf(kv.key, kv.value); err != nil {
			return err
		}
	}
	strictValue := "0"
	if strict {
		strictValue = "1"
	}
	return ctrl.SetConf("StrictNodes", strictValue)
}

// Stop shuts the instance down: control connection first, then the process.
func (i *Instance) Stop() error {
	i.mu.Lock()
	ctrl := i.ctrl
	i.ctrl = nil
	i.ready = false
	i.mu.Unlock()

	if ctrl != nil {
		_ = ctrl.Close()
	}
	return i.proc.Stop()
}

// Restart stops tor, optionally wipes its state, and starts it again.
//
// Wiping forces a completely new identity: fresh guards, fresh circuits, no
// cached consensus. The wipe happens strictly after Stop returns, because
// deleting a live tor's DataDirectory leaves the respawn inheriting
// half-removed state.
func (i *Instance) Restart(ctx context.Context, wipeState bool) error {
	if err := i.Stop(); err != nil {
		return fmt.Errorf("instance %d: stop before restart: %w", i.cfg.Index, err)
	}

	if wipeState {
		if err := os.RemoveAll(i.cfg.DataDirectory); err != nil {
			return fmt.Errorf("instance %d: wipe data directory: %w", i.cfg.Index, err)
		}
		i.log.Info("data directory wiped")
	}

	// A Process cannot be restarted, so build a fresh one over the same config.
	i.proc = NewProcess(i.binry, i.cfg, i.onTorLog)
	i.retireExit()

	return i.Start(ctx)
}

// Wait blocks until the tor process exits.
func (i *Instance) Wait() error { return i.proc.Wait() }

// onTorLog forwards tor's own log lines, mapping its levels onto slog's.
func (i *Instance) onTorLog(level, message string) {
	switch level {
	case "err":
		i.log.Error("tor", "msg", message)
	case "warn":
		i.log.Warn("tor", "msg", message)
	case "notice":
		i.log.Debug("tor", "msg", message)
	default:
		i.log.Debug("tor", "level", level, "msg", message)
	}
}
