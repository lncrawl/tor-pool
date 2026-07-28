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

// controlDialTimeout bounds a reconnect to the control port.
//
// Connect retries until its context is done, which is right at startup when tor
// is still opening the port. A mid-life reconnect is different: the port is
// either there or the process is in trouble, and the caller is usually a request
// that must not hang on it.
const controlDialTimeout = 5 * time.Second

// ErrNoControl means the instance has no usable control connection, so nothing
// that needs one can be done to it right now.
var ErrNoControl = errors.New("tor: instance has no control connection")

// ErrControlBusy means another command holds the control connection. Reported
// rather than waited out by the pollers, whose next tick is a better place to
// try again than a queue behind a NEWNYM cooldown.
var ErrControlBusy = errors.New("tor: control connection is busy")

// Instance is one supervised tor process together with its control connection.
//
// It owns the lifecycle of both: the process, the authenticated control
// connection, and the state that says whether the pair is usable. Higher layers
// treat it as an opaque backend they can route to, rotate, or restart.
type Instance struct {
	cfg   InstanceConfig
	log   *slog.Logger
	binry string

	// startMu serialises the launch sequence. A restart must never run
	// alongside the Start it is replacing: both write the torrc and spawn tor
	// against the same ports and DataDirectory, and the loser fails to bind in
	// a way that reads as a network problem. Stop deliberately does not take
	// this — it is what interrupts an in-flight Start.
	startMu sync.Mutex

	// ctrlMu serialises control-port commands. The protocol is one synchronous
	// request/reply stream, so two overlapping commands read each other's
	// replies. It is separate from mu because a command may block for a long
	// time and mu must never be held across that.
	ctrlMu sync.Mutex

	mu           sync.Mutex
	proc         *Process
	ctrl         *Control
	bootstrap    int
	bootstrapAt  time.Time
	starting     bool
	ready        bool
	startedAt    time.Time
	exitNode     ExitNode
	exitConfirmT bool
	pinnedExit   string

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

// process returns the current process supervisor.
//
// It is replaced on every restart, so every read has to go through the lock:
// the supervisor loop and the API both ask about liveness while a restart is
// swapping it out.
func (i *Instance) process() *Process {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.proc
}

// Start launches tor, waits for its control port, and blocks until it has
// bootstrapped. It returns a non-nil error if any of those steps fails.
func (i *Instance) Start(ctx context.Context) error {
	i.startMu.Lock()
	defer i.startMu.Unlock()
	return i.startLocked(ctx)
}

func (i *Instance) startLocked(ctx context.Context) error {
	now := time.Now()
	i.mu.Lock()
	proc := i.proc
	i.startedAt = now
	i.bootstrapAt = now
	i.starting = true
	i.ready = false
	i.bootstrap = 0
	i.mu.Unlock()

	defer func() {
		i.mu.Lock()
		i.starting = false
		i.mu.Unlock()
	}()

	if err := proc.Start(ctx); err != nil {
		return fmt.Errorf("instance %d: %w", i.cfg.Index, err)
	}
	i.log.Info("tor started", "pid", proc.Pid())

	// A tor that dies during startup must not leave the rest of this function
	// waiting on it. Connect retries until its context is done, and the auth
	// cookie outlives the process that wrote it — so against a dead tor it would
	// retry forever while holding startMu, which is the lock the restart that
	// would fix it needs.
	startCtx, abandon := context.WithCancel(ctx)
	defer abandon()
	go func() {
		_ = proc.Wait()
		abandon()
	}()

	ctrl, err := Connect(startCtx, i.cfg)
	if err != nil {
		return fmt.Errorf("instance %d: %w", i.cfg.Index, err)
	}
	i.mu.Lock()
	i.ctrl = ctrl
	i.mu.Unlock()
	i.log.Debug("control port authenticated")

	err = WaitBootstrapped(startCtx, ctrl, bootstrapPoll, func(pct int) {
		i.mu.Lock()
		changed := pct > i.bootstrap
		i.bootstrap = pct
		if changed {
			// Only forward progress resets the clock: tor reporting the same
			// percentage for minutes is precisely the stall worth catching.
			i.bootstrapAt = time.Now()
		}
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
	startedAt := i.startedAt
	i.mu.Unlock()
	i.log.Info("bootstrapped", "took", time.Since(startedAt).Round(time.Millisecond))

	return nil
}

// Ready reports whether this instance has bootstrapped and is routable.
func (i *Instance) Ready() bool {
	i.mu.Lock()
	ready := i.ready
	i.mu.Unlock()
	return ready && i.Running()
}

// Bootstrap reports the last known bootstrap percentage.
func (i *Instance) Bootstrap() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.bootstrap
}

// BootstrapProgress reports the last known bootstrap percentage and when it last
// advanced.
//
// A bootstrap that stops advancing is the failure mode nothing else catches: the
// process is alive so the supervisor is happy, and the instance takes no traffic
// so the failure ladder never hears about it. The pool compares the age of this
// against its stall timeout.
func (i *Instance) BootstrapProgress() (pct int, since time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.bootstrap, i.bootstrapAt
}

// Starting reports whether a launch sequence is in flight.
func (i *Instance) Starting() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.starting
}

// StartedAt reports when the current process was launched.
func (i *Instance) StartedAt() time.Time {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.startedAt
}

// Running reports whether the tor process is alive, regardless of bootstrap.
func (i *Instance) Running() bool { return i.process().Running() }

// Pid returns the tor process id, or 0 when not running.
func (i *Instance) Pid() int { return i.process().Pid() }

// withControl runs fn against the authenticated control connection, redialling
// first if the previous one died or was left out of sync.
//
// Nothing else reconnects: a control connection lost while tor keeps running
// leaves an instance that still serves traffic but can never be rotated or
// report its exit again.
func (i *Instance) withControl(ctx context.Context, fn func(*Control) error) error {
	i.ctrlMu.Lock()
	defer i.ctrlMu.Unlock()
	return i.useControlLocked(ctx, fn)
}

// tryWithControl is withControl for pollers: it gives up immediately rather than
// queueing behind a command that may take as long as tor's NEWNYM cooldown.
func (i *Instance) tryWithControl(ctx context.Context, fn func(*Control) error) error {
	if !i.ctrlMu.TryLock() {
		return ErrControlBusy
	}
	defer i.ctrlMu.Unlock()
	return i.useControlLocked(ctx, fn)
}

func (i *Instance) useControlLocked(ctx context.Context, fn func(*Control) error) error {
	ctrl, err := i.controlLocked(ctx)
	if err != nil {
		return err
	}
	err = fn(ctrl)
	if ctrl.Broken() {
		// The reply stream is unusable; drop it so the next call redials.
		i.mu.Lock()
		if i.ctrl == ctrl {
			i.ctrl = nil
		}
		i.mu.Unlock()
		_ = ctrl.Close()
		i.log.Debug("control connection discarded after an out-of-sync command")
	}
	return err
}

// controlLocked returns a usable control connection, dialling a replacement if
// the current one is missing or broken. Callers must hold ctrlMu.
func (i *Instance) controlLocked(ctx context.Context) (*Control, error) {
	i.mu.Lock()
	ctrl := i.ctrl
	i.mu.Unlock()

	if ctrl != nil && !ctrl.Broken() {
		return ctrl, nil
	}
	if !i.Running() {
		return nil, ErrNoControl
	}

	dialCtx, cancel := context.WithTimeout(ctx, controlDialTimeout)
	defer cancel()
	replacement, err := Connect(dialCtx, i.cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoControl, err)
	}

	i.mu.Lock()
	i.ctrl = replacement
	i.mu.Unlock()
	i.log.Info("control connection re-established")
	return replacement, nil
}

// Newnym requests a fresh circuit, waiting out tor's cooldown first.
//
// The wait happens with the control lock released. Holding it across a ten
// second sleep blocked everything else that speaks to this instance — including
// the exit-refresh poller, which then blocked the pool's maintenance loop.
func (i *Instance) Newnym(ctx context.Context) error {
	for {
		var wait time.Duration
		err := i.withControl(ctx, func(ctrl *Control) error {
			if wait = ctrl.NewnymWait(); wait > 0 {
				return nil
			}
			return i.newnymLocked(ctrl)
		})
		if err != nil || wait == 0 {
			return err
		}

		i.log.Debug("waiting out the newnym cooldown", "remaining", wait.Round(time.Millisecond))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// newnymLocked signals NEWNYM and clears the circuits it retired. Callers must
// hold ctrlMu.
func (i *Instance) newnymLocked(ctrl *Control) error {
	if err := ctrl.Signal("NEWNYM"); err != nil {
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
	return i.refreshExit(context.Background(), false)
}

// TryRefreshExitNode is RefreshExitNode for the periodic poller: it skips the
// instance rather than waiting for a command in progress.
func (i *Instance) TryRefreshExitNode() (ExitNode, error) {
	return i.refreshExit(context.Background(), true)
}

func (i *Instance) refreshExit(ctx context.Context, try bool) (ExitNode, error) {
	var (
		node      ExitNode
		confirmed bool
	)
	read := func(ctrl *Control) error {
		var err error
		node, confirmed, err = ctrl.ExitNode()
		return err
	}

	var err error
	if try {
		err = i.tryWithControl(ctx, read)
	} else {
		err = i.withControl(ctx, read)
	}
	if err != nil {
		return ExitNode{}, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	// An inferred exit must not displace one traffic confirmed. Tor keeps
	// several circuits standing and builds more preemptively, so an unconfirmed
	// read is a guess among them — publishing it is what made the exit IP appear
	// to jump around after a rotation before settling.
	if confirmed || !i.exitConfirmT {
		i.exitNode = node
		i.exitConfirmT = confirmed
		i.retiredExit = ExitNode{}
	}
	return i.exitNode, nil
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
		node, err := i.refreshExit(ctx, false)
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

// ExitConfirmed reports whether traffic has confirmed the reported exit, as
// opposed to it being inferred from the circuits tor happens to be holding.
func (i *Instance) ExitConfirmed() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.exitConfirmT
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
	i.exitConfirmT = false
}

// SetExitPolicy applies exit-node selection at runtime.
func (i *Instance) SetExitPolicy(exitNodes, excludeExitNodes string, strict bool) error {
	return i.withControl(context.Background(), func(ctrl *Control) error {
		return ctrl.SetConfAll(
			ConfValue{"ExitNodes", exitNodes},
			ConfValue{"ExcludeExitNodes", excludeExitNodes},
			ConfValue{"StrictNodes", torBool(strict)},
		)
	})
}

// PinExit locks every circuit this instance builds from now on to one exit relay,
// and closes the standing circuits that leave through a different one.
//
// This is what makes "one instance is one exit identity" literally true. Tor's
// own path selection gives an instance several exit-bearing circuits at once and
// spreads successive streams across them, so without a pin a caller's exit IP
// changes under it even though nothing rotated. The cost is that the instance
// now depends on one relay: if it stops accepting the traffic, the requests fail
// and the failure ladder has to pick a different exit.
func (i *Instance) PinExit(ctx context.Context, fingerprint string) error {
	if fingerprint == "" {
		return errors.New("tor: cannot pin to an empty exit fingerprint")
	}
	err := i.withControl(ctx, func(ctrl *Control) error {
		if err := ctrl.SetConfAll(
			ConfValue{"ExitNodes", "$" + fingerprint},
			// The configured exclusions still apply; the temporary one a
			// rotation adds to avoid reusing the burnt relay does not.
			ConfValue{"ExcludeExitNodes", i.cfg.ExcludeExitNodes},
			ConfValue{"StrictNodes", "1"},
		); err != nil {
			return err
		}
		// ExitNodes only constrains circuits tor builds from here on. The ones
		// already standing exit elsewhere, and a stream attached to one of them
		// would leave through a relay this instance is no longer claiming.
		closed, err := ctrl.CloseCircuitsExceptExit(fingerprint)
		if err != nil {
			i.log.Warn("closing off-pin circuits failed", "closed", closed, "error", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	i.mu.Lock()
	i.pinnedExit = fingerprint
	i.mu.Unlock()
	i.log.Info("exit relay pinned", "fingerprint", fingerprint)
	return nil
}

// UnpinExit restores the configured exit policy, optionally keeping tor away
// from one relay while it chooses the next one.
func (i *Instance) UnpinExit(ctx context.Context, avoid string) error {
	exclude := i.cfg.ExcludeExitNodes
	if avoid != "" {
		if exclude != "" {
			exclude += ","
		}
		exclude += "$" + avoid
	}

	err := i.withControl(ctx, func(ctrl *Control) error {
		return ctrl.SetConfAll(
			ConfValue{"ExitNodes", i.cfg.ExitNodes},
			ConfValue{"ExcludeExitNodes", exclude},
			ConfValue{"StrictNodes", torBool(i.cfg.StrictNodes)},
		)
	})
	if err != nil {
		return err
	}

	i.mu.Lock()
	i.pinnedExit = ""
	i.mu.Unlock()
	return nil
}

// PinnedExit returns the fingerprint this instance is locked to, or empty when
// tor is choosing exits freely.
func (i *Instance) PinnedExit() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.pinnedExit
}

// Stop shuts the instance down: control connection first, then the process.
//
// It deliberately does not take startMu — stopping is how an in-flight Start is
// interrupted, and waiting for that Start to finish first would deadlock a
// restart against the very launch it is replacing.
func (i *Instance) Stop() error {
	i.mu.Lock()
	ctrl := i.ctrl
	proc := i.proc
	i.ctrl = nil
	i.ready = false
	i.mu.Unlock()

	if ctrl != nil {
		_ = ctrl.Close()
	}
	return proc.Stop()
}

// Restart stops tor, optionally wipes its state, and starts it again.
//
// Wiping forces a completely new identity: fresh guards, fresh circuits, no
// cached consensus. The wipe happens strictly after Stop returns, because
// deleting a live tor's DataDirectory leaves the respawn inheriting
// half-removed state.
func (i *Instance) Restart(ctx context.Context, wipeState bool) error {
	// Stop first, outside the lock: it is what unblocks an in-flight Start,
	// which then releases startMu to this call.
	if err := i.Stop(); err != nil {
		return fmt.Errorf("instance %d: stop before restart: %w", i.cfg.Index, err)
	}

	i.startMu.Lock()
	defer i.startMu.Unlock()

	if wipeState {
		if err := os.RemoveAll(i.cfg.DataDirectory); err != nil {
			return fmt.Errorf("instance %d: wipe data directory: %w", i.cfg.Index, err)
		}
		i.log.Info("data directory wiped")
	}

	// A Process cannot be restarted, so build a fresh one over the same config.
	// The pin goes with the old process: nothing is configured on a tor that has
	// not started yet.
	i.mu.Lock()
	i.proc = NewProcess(i.binry, i.cfg, i.onTorLog)
	i.pinnedExit = ""
	i.mu.Unlock()
	i.retireExit()

	return i.startLocked(ctx)
}

// Wait blocks until the tor process exits.
func (i *Instance) Wait() error { return i.process().Wait() }

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
