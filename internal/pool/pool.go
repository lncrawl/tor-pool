package pool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/stats"
	"github.com/lncrawl/tor-pool/internal/tor"
)

// Outcome is what a completed connection did.
type Outcome struct {
	Instance  int
	BytesUp   int64
	BytesDown int64
	// Latency is the time to establish the connection through tor, not the
	// duration of the transfer. It is the part that reflects instance health.
	Latency time.Duration
	Failed  bool
}

// ErrNoInstance means nothing in the pool can currently carry traffic.
//
// Callers surface this rather than queueing: a scraper's own direct-fallback or
// retry logic handles it far better than an unbounded wait here would.
var ErrNoInstance = errors.New("pool: no healthy instance available")

// ErrNoSuchInstance means the operation named an instance the fleet does not
// have — including one retired between a caller's check and its request, which
// is a race the dashboard hits whenever a resize overlaps a row action.
//
// Exported so the API can answer 404 rather than 500: a caller acting on a
// vanished instance made a stale request, it did not break the server.
var ErrNoSuchInstance = errors.New("no such instance")

// ErrInstanceNotReady means the operation needs a bootstrapped instance and this
// one is not there yet.
//
// Rotating an instance that has no circuits is not merely pointless: it spends
// the NEWNYM cooldown, so the rotation the operator asks for once it *is* ready
// gets silently coalesced away.
var ErrInstanceNotReady = errors.New("instance is not ready")

const (
	// sweepInterval is how often idle sessions are collected.
	sweepInterval = 30 * time.Second

	// eventLogSize is how many audit entries are retained in memory.
	eventLogSize = 2000

	// superviseInterval is how often dead tor processes are looked for.
	superviseInterval = 10 * time.Second

	// exitSettleTimeout bounds how long a rotation waits for tor to build the
	// circuit that replaces the one it just retired. Until then the instance has
	// no exit to report at all, and answering the caller with the pre-rotation
	// exit would be answering with a relay it no longer uses.
	//
	// Generous, because nothing waits on it: the rotation is acknowledged before
	// this runs, and an instance still counts as rotating until it finishes — so
	// the only thing a longer budget costs is steering callers to instances that
	// can already serve them. A shorter one released the instance while tor was
	// still building, and its next caller paid for the build instead.
	exitSettleTimeout = 10 * time.Second

	// exitRefreshInterval is how often each instance's exit relay is re-read.
	//
	// This has to be polled rather than cached once: tor retires circuits on its
	// own schedule, and a stale value means the API reports an exit that no
	// traffic is using. It is a local control-port query, not Tor traffic, so
	// polling is cheap.
	exitRefreshInterval = 5 * time.Second

	// rotationGrace is how long after a rotation an instance stops being blamed
	// for failures.
	//
	// A rotation throws away the circuits requests were about to use, so the
	// requests that were mid-flight fail — through no fault of the instance.
	// Scoring those was self-defeating: rotating a healthy instance a few times
	// was enough to quarantine it, which triggered remediation, which rotated it
	// again. Long enough to cover a circuit rebuild, short enough that a
	// genuinely broken instance is still caught on its next request.
	rotationGrace = 5 * time.Second
)

// Pool routes callers to tor instances and keeps them pinned.
type Pool struct {
	cfg      *config.Config
	fleet    *tor.Fleet
	sessions *sessions
	log      *slog.Logger

	stats  *stats.Collector
	events *stats.EventLog

	sampleMu       sync.Mutex
	lastExitSample map[int]time.Time

	healthMu sync.Mutex
	health   map[int]*health

	// ctx is the pool's own lifetime, captured by Run. Remediation uses it so a
	// restart is not abandoned when the request that triggered it goes away.
	ctx context.Context

	// remediating guards against two remediations running on one instance at
	// once, which could restart tor underneath itself.
	remediating map[int]bool

	// startAttempts counts consecutive failed launches per instance, so a second
	// attempt can wipe the state a first one preserved.
	startAttempts map[int]int

	// rotating counts the rotations in flight per instance, so assignment can
	// steer new callers away from an instance that has no circuits right now.
	rotating map[int]int

	// quietUntil is when an instance stops being excused for failures caused by
	// its own rotation.
	quietUntil map[int]time.Time

	// exitSince is when each instance's current exit identity began, which is
	// what EXIT_TTL is measured against.
	exitSince map[int]time.Time

	// sweeping guards a pool-wide rotation, which runs one instance at a time
	// and would otherwise be started again by every click while it ran.
	sweeping bool
}

// New builds a pool over an existing fleet.
func New(cfg *config.Config, fleet *tor.Fleet, log *slog.Logger) *Pool {
	return &Pool{
		cfg:            cfg,
		fleet:          fleet,
		sessions:       newSessions(cfg.SessionTTL, cfg.MaxSessions),
		log:            log,
		lastExitSample: make(map[int]time.Time),
		stats:          stats.NewCollector(cfg.HistoryResolution, cfg.HistoryWindow),
		events:         stats.NewEventLog(eventLogSize),
		health:         make(map[int]*health),
		remediating:    make(map[int]bool),
		startAttempts:  make(map[int]int),
		rotating:       make(map[int]int),
		quietUntil:     make(map[int]time.Time),
		exitSince:      make(map[int]time.Time),
	}
}

// policy derives the health tuning from configuration.
func (p *Pool) policy() healthPolicy {
	return healthPolicy{
		Window:           p.cfg.FailureWindow,
		MaxInWindow:      p.cfg.QuarantineFailures,
		MaxConsecutive:   p.cfg.QuarantineConsecutive,
		EscalationWindow: p.cfg.EscalationWindow,
		Backoff:          p.cfg.RemediationBackoff,
		MaxBackoff:       p.cfg.MaxRemediationBackoff,
	}
}

// healthFor returns an instance's health record, creating it on first sight.
func (p *Pool) healthFor(instance int) *health {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()

	h, ok := p.health[instance]
	if !ok {
		h = newHealth()
		p.health[instance] = h
	}
	return h
}

// Health returns the reportable health of every instance.
func (p *Pool) Health() map[int]HealthView {
	now := time.Now()
	policy := p.policy()

	instances := p.fleet.Instances()
	out := make(map[int]HealthView, len(instances))
	for _, inst := range instances {
		out[inst.Index()] = p.healthFor(inst.Index()).snapshot(now, policy)
	}
	return out
}

// QuarantineScore is the weighted failure score that takes an instance out of
// rotation.
//
// Exported for reporting: a failure score means nothing without the threshold it
// is measured against, and QUARANTINE_FAILURES is not that threshold — it counts
// baseline failures, while a captcha is worth several of those.
func (p *Pool) QuarantineScore() int { return p.policy().quarantineScore() }

// forgetInstance drops health state for a retired instance so the maps do not
// grow across resizes.
func (p *Pool) forgetInstance(instance int) {
	p.healthMu.Lock()
	delete(p.health, instance)
	delete(p.remediating, instance)
	delete(p.startAttempts, instance)
	delete(p.rotating, instance)
	delete(p.quietUntil, instance)
	delete(p.exitSince, instance)
	p.healthMu.Unlock()

	p.sampleMu.Lock()
	delete(p.lastExitSample, instance)
	p.sampleMu.Unlock()

	// Indexes are reused, so a retired instance's counters would otherwise be
	// inherited by whatever takes its place.
	p.stats.Forget(instance)
}

// Fleet exposes the underlying fleet for lifecycle operations.
func (p *Pool) Fleet() *tor.Fleet { return p.fleet }

// Run maintains the pool until ctx is cancelled: the idle-session sweep, process
// supervision, the exit-relay poll, and the scheduled rotation of exits that have
// outlived EXIT_TTL.
//
// The exit poll runs in its own goroutine. It talks to every instance's control
// port, and a control port can be busy for as long as tor's NEWNYM cooldown — so
// sharing a loop with the session sweep and the process supervisor meant a
// pool-wide rotation stopped both of them for tens of seconds.
func (p *Pool) Run(ctx context.Context) {
	p.healthMu.Lock()
	p.ctx = ctx
	p.healthMu.Unlock()

	go p.runExitPoll(ctx)
	if p.cfg.ExitTTL > 0 {
		go p.runRotationSchedule(ctx)
	}

	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()
	supervise := time.NewTicker(superviseInterval)
	defer supervise.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			if n := p.sessions.sweep(time.Now()); n > 0 {
				p.log.Debug("idle sessions expired", "count", n)
			}
		case <-supervise.C:
			p.superviseProcesses(ctx)
		}
	}
}

// runExitPoll keeps each instance's reported exit relay current.
func (p *Pool) runExitPoll(ctx context.Context) {
	ticker := time.NewTicker(exitRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.RefreshExitNodes()
			p.pinExits(ctx)
			p.stats.RecordRoutable(p.RoutableCount())
		}
	}
}

// RefreshExitNodes re-reads the current exit relay of every ready instance.
//
// Failures are expected and ignored: an instance with no circuit yet simply has
// no exit to report, and one whose control connection is mid-command is skipped
// rather than queued behind it — the next tick is soon enough.
func (p *Pool) RefreshExitNodes() {
	for _, inst := range p.readyInstances() {
		if _, err := inst.TryRefreshExitNode(); err != nil {
			p.log.Debug("exit node unavailable", "instance", inst.Index(), "error", err)
		}
	}
}

// pinExits locks any ready instance that is not pinned to an exit relay yet.
//
// Instances arrive unpinned from boot, from a restart and from a resize, so this
// runs on the poll rather than at any one of those moments. Instances still
// rotating are skipped: their rotation pins them at the end, and pinning them to
// the exit they are in the middle of discarding would undo it.
func (p *Pool) pinExits(ctx context.Context) {
	if !p.cfg.PinExitRelay {
		return
	}
	for _, inst := range p.readyInstances() {
		index := inst.Index()
		if inst.PinnedExit() != "" || p.rotationWindow(index, time.Now()) {
			continue
		}
		node := inst.ExitNode()
		if node.Fingerprint == "" {
			continue
		}
		if err := inst.PinExit(ctx, node.Fingerprint); err != nil {
			p.log.Warn("pinning the exit relay failed", "instance", index, "error", err)
			continue
		}
		p.events.Instance(stats.EventInstance, index,
			"pinned to exit relay "+node.Address, node.Fingerprint)
	}
}

// Route returns the instance a session should use, pinning it on first sight.
//
// This is the hot path. A session keeps its instance until it rotates or the
// instance stops being routable — that stickiness is the whole point of the
// pool, so reassignment only ever happens for a reason worth logging.
func (p *Pool) Route(key string) (*tor.Instance, error) {
	now := time.Now()
	avoid := -1

	// Look up before accounting: a reassignment must not be counted as two
	// requests on the session.
	if sess, ok := p.sessions.lookup(key); ok {
		inst, alive := p.fleet.Get(sess.Instance)
		switch {
		case !alive || !inst.Ready():
			p.log.Info("session's instance is unavailable, reassigning",
				"session", key, "previous_instance", sess.Instance)
			p.sessions.drop(key)

		case p.cfg.DrainOnRotate && p.isRotating(sess.Instance):
			// The instance has just thrown its circuits away, so this request
			// would wait on a rebuild it never asked for. Diverting the session
			// covers the ones already pinned when the rotation began; this covers
			// the ones that arrive during it.
			p.log.Debug("session's instance is rotating, reassigning",
				"session", key, "previous_instance", sess.Instance)
			avoid = sess.Instance

		default:
			p.sessions.begin(key, now)
			return inst, nil
		}
	}

	inst, err := p.assign(key, now, avoid)
	if err != nil {
		return nil, err
	}
	p.sessions.begin(key, now)
	return inst, nil
}

// assign pins key to the least loaded healthy instance, avoiding exclude when
// it can.
func (p *Pool) assign(key string, now time.Time, exclude int) (*tor.Instance, error) {
	candidates := p.readyInstances()
	if len(candidates) == 0 {
		return nil, ErrNoInstance
	}
	candidates = p.preferSettled(candidates)

	inst := pick(candidates, p.sessions.countByInstance(), exclude)
	if inst == nil {
		return nil, ErrNoInstance
	}

	if p.sessions.pin(key, inst.Index(), now) {
		p.log.Info("session pinned", "session", key, "instance", inst.Index())
	}
	return inst, nil
}

// Finish records the outcome of a request against its session.
//
// A failure is not scored here: whoever detected it already attributed it to a
// specific instance, and doing it twice would halve the effective quarantine
// threshold.
func (p *Pool) Finish(key string, out Outcome) {
	p.sessions.finish(key, out.BytesUp, out.BytesDown, out.Failed)
	p.stats.RecordRequest(out.Instance, out.BytesUp, out.BytesDown, out.Latency, out.Failed)
	if out.Failed {
		return
	}
	p.RecordSuccess(out.Instance)
}

// Stats exposes the collector for reporting.
func (p *Pool) Stats() *stats.Collector { return p.stats }

// Events exposes the audit log.
func (p *Pool) Events() *stats.EventLog { return p.events }

// RotateSession moves a session to a different instance.
//
// Reassignment is immediate, which is the pool's main advantage over a single
// tor: NEWNYM has a 10 second cooldown, while moving to an already-built
// instance costs nothing. newnym additionally asks the vacated instance for a
// fresh circuit, which is the slow path and only worth it when the caller
// believes that exit itself is burnt.
func (p *Pool) RotateSession(key string, newnym bool) (*tor.Instance, error) {
	previous := -1
	if sess, ok := p.sessions.lookup(key); ok {
		previous = sess.Instance
	}

	inst, err := p.assign(key, time.Now(), previous)
	if err != nil {
		return nil, err
	}

	// Avoiding the previous instance is a preference, not a guarantee: with one
	// routable instance the caller lands back where it started. Rotating in place
	// is then the only way to keep the promise the call makes, because a rotation
	// that leaves the exit IP alone did nothing at all.
	stayedPut := inst.Index() == previous
	if (newnym || stayedPut) && previous >= 0 {
		// The vacated instance rotates exactly like an operator-requested rotation
		// would, including retiring its circuits and moving the *other* sessions
		// off it: they are pinned to the exit this caller just declared burnt.
		// It blocks on tor's cooldown, so it finishes in the background.
		if err := p.StartRotateInstance(previous); err != nil &&
			!errors.Is(err, ErrInstanceNotReady) && !errors.Is(err, ErrNoSuchInstance) {
			p.log.Warn("rotating vacated instance failed", "instance", previous, "error", err)
		}
	}

	p.log.Info("session rotated", "session", key,
		"from_instance", previous, "to_instance", inst.Index(),
		"newnym", newnym, "same_instance", stayedPut)
	p.events.Session(stats.EventRotate, key, inst.Index(),
		fmt.Sprintf("session rotated from instance %d", previous))
	return inst, nil
}

// ReportFailure records a failure a client observed itself.
//
// This is the only signal that catches soft blocks: a 403, a 429 or a captcha
// is invisible to the balancer because it is inside an HTTPS tunnel. The kind is
// what the pool acts on; reason is the caller's own free text, kept for the
// audit log and never parsed here.
func (p *Pool) ReportFailure(key string, kind FailureKind, reason string) (instance int, ok bool) {
	instance, ok = p.sessions.recordFailure(key)
	if !ok {
		return 0, false
	}
	p.log.Info("client reported failure",
		"session", key, "instance", instance, "kind", kind, "reason", reason)
	p.RecordFailure(instance, SourceClient, kind, reason)
	return instance, true
}

// DropSession removes a session's pinning; its next request is reassigned.
func (p *Pool) DropSession(key string) bool { return p.sessions.drop(key) }

// Sessions returns a snapshot of every live session.
func (p *Pool) Sessions() []Session { return p.sessions.list() }

// Session returns one session by key.
func (p *Pool) Session(key string) (Session, bool) { return p.sessions.lookup(key) }

// RoutableCount reports how many instances can actually take traffic right now.
//
// This is not the same as the number of bootstrapped processes: a quarantined
// instance is alive and fully bootstrapped but must not be routed to. Liveness
// checks have to use this one, or a pool with everything quarantined reports
// itself healthy while refusing every request.
func (p *Pool) RoutableCount() int { return len(p.readyInstances()) }

// SessionCount reports how many sessions are pinned.
func (p *Pool) SessionCount() int { return p.sessions.count() }

// SessionsPerInstance reports how many sessions each instance carries.
func (p *Pool) SessionsPerInstance() map[int]int { return p.sessions.countByInstance() }

// beginRotation marks an instance as mid-rotation, so nothing new is pinned to
// it while it has no circuits. It is a count, not a flag: a pool-wide rotation
// and a session rotation can overlap on one instance, and the first to finish
// must not clear the other's mark.
func (p *Pool) beginRotation(instance int) {
	p.healthMu.Lock()
	p.rotating[instance]++
	p.healthMu.Unlock()
}

// beginRotationExclusive is beginRotation for a caller that has nothing to add to
// a rotation already in progress. It reports whether it took the mark.
//
// Rotations do not usefully stack: each waits out tor's cooldown, so a client
// that asks twice in quick succession would queue a second ten second wait for an
// identity change the first one already delivered.
func (p *Pool) beginRotationExclusive(instance int) bool {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	if p.rotating[instance] > 0 {
		return false
	}
	p.rotating[instance]++
	return true
}

// endRotation clears the mark and starts the grace period during which the
// instance is not blamed for the failures its own rotation caused.
func (p *Pool) endRotation(instance int) {
	now := time.Now()

	p.healthMu.Lock()
	if p.rotating[instance] <= 1 {
		delete(p.rotating, instance)
	} else {
		p.rotating[instance]--
	}
	p.quietUntil[instance] = now.Add(rotationGrace)
	// Every rotation ends here, so this is the one place the scheduled-rotation
	// clock has to restart — an attempt that failed against a wedged control port
	// included, or the schedule would retry it on every tick.
	p.exitSince[instance] = now
	p.healthMu.Unlock()
}

// isRotating reports whether a rotation is in flight on an instance.
func (p *Pool) isRotating(instance int) bool {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	return p.rotating[instance] > 0
}

// rotationWindow reports whether an instance is rotating or still inside the
// grace period that follows one.
func (p *Pool) rotationWindow(instance int, now time.Time) bool {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	return p.rotating[instance] > 0 || now.Before(p.quietUntil[instance])
}

// preferSettled drops the instances that are mid-rotation, unless that would
// leave nothing to choose from.
//
// A rotating instance has just closed its circuits and has none to offer for a
// second or two, so a caller pinned to it there and then would wait on — or fail
// against — a rotation it never asked for. It stays a candidate of last resort
// because a single-instance pool must still route.
func (p *Pool) preferSettled(candidates []*tor.Instance) []*tor.Instance {
	p.healthMu.Lock()
	rotating := len(p.rotating)
	settled := make([]*tor.Instance, 0, len(candidates))
	if rotating > 0 {
		for _, inst := range candidates {
			if p.rotating[inst.Index()] == 0 {
				settled = append(settled, inst)
			}
		}
	}
	p.healthMu.Unlock()

	if rotating == 0 || len(settled) == 0 {
		return candidates
	}
	return settled
}

// divertSessions repins every session on an instance to a different one, and
// reports how many moved.
//
// Reassignment is immediate rather than lazy, unlike a drain. Unpinning would
// leave the choice to each session's next request, and an instance that has just
// lost all of its sessions looks like the least loaded one — so the displaced
// callers would land straight back on the instance being rotated. Pinning them
// one at a time still spreads them, because each pin counts towards the next
// pick.
//
// Connections already in flight keep the instance they were dialled through;
// only the next one is affected.
func (p *Pool) divertSessions(instance int) int {
	now := time.Now()

	var moved int
	for _, sess := range p.sessions.list() {
		if sess.Instance != instance {
			continue
		}
		if _, err := p.assign(sess.Key, now, instance); err != nil {
			// Nothing else can take it. Leaving the pinning alone beats dropping
			// it: the instance is losing its exit, not its ability to serve.
			p.log.Warn("cannot divert session off rotating instance",
				"session", sess.Key, "instance", instance, "error", err)
			continue
		}
		moved++
	}
	return moved
}

// DrainInstance unpins every session on an instance so they move elsewhere.
func (p *Pool) DrainInstance(instance int) int {
	n := p.sessions.unpinInstance(instance)
	if n > 0 {
		p.log.Info("instance drained", "instance", instance, "sessions_moved", n)
	}
	return n
}

// readyInstances returns the instances that can currently carry traffic.
//
// An instance must be both bootstrapped *and* in a routable health state: a
// quarantined instance is alive and would happily serve, which is exactly why
// the health gate has to be checked here and not left to the process state.
func (p *Pool) readyInstances() []*tor.Instance {
	now := time.Now()
	all := p.fleet.Instances()

	ready := make([]*tor.Instance, 0, len(all))
	for _, inst := range all {
		if !inst.Ready() {
			continue
		}
		h := p.healthFor(inst.Index())
		h.markReady()
		if h.routable(now) {
			ready = append(ready, inst)
		}
	}
	return ready
}
