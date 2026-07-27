package pool

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/tor"
)

// ErrNoInstance means nothing in the pool can currently carry traffic.
//
// Callers surface this rather than queueing: a scraper's own direct-fallback or
// retry logic handles it far better than an unbounded wait here would.
var ErrNoInstance = errors.New("pool: no healthy instance available")

const (
	// sweepInterval is how often idle sessions are collected.
	sweepInterval = 30 * time.Second

	// superviseInterval is how often dead tor processes are looked for.
	superviseInterval = 10 * time.Second

	// exitRefreshInterval is how often each instance's exit relay is re-read.
	//
	// This has to be polled rather than cached once: tor retires circuits on its
	// own schedule, and a stale value means the API reports an exit that no
	// traffic is using. It is a local control-port query, not Tor traffic, so
	// polling is cheap.
	exitRefreshInterval = 5 * time.Second
)

// Pool routes callers to tor instances and keeps them pinned.
type Pool struct {
	cfg      *config.Config
	fleet    *tor.Fleet
	sessions *sessions
	log      *slog.Logger

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
}

// New builds a pool over an existing fleet.
func New(cfg *config.Config, fleet *tor.Fleet, log *slog.Logger) *Pool {
	return &Pool{
		cfg:            cfg,
		fleet:          fleet,
		sessions:       newSessions(cfg.SessionTTL, cfg.MaxSessions),
		log:            log,
		lastExitSample: make(map[int]time.Time),
		health:         make(map[int]*health),
		remediating:    make(map[int]bool),
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
	window := p.cfg.FailureWindow

	instances := p.fleet.Instances()
	out := make(map[int]HealthView, len(instances))
	for _, inst := range instances {
		out[inst.Index()] = p.healthFor(inst.Index()).snapshot(now, window)
	}
	return out
}

// forgetInstance drops health state for a retired instance so the maps do not
// grow across resizes.
func (p *Pool) forgetInstance(instance int) {
	p.healthMu.Lock()
	delete(p.health, instance)
	delete(p.remediating, instance)
	p.healthMu.Unlock()

	p.sampleMu.Lock()
	delete(p.lastExitSample, instance)
	p.sampleMu.Unlock()
}

// Fleet exposes the underlying fleet for lifecycle operations.
func (p *Pool) Fleet() *tor.Fleet { return p.fleet }

// Run maintains the pool until ctx is cancelled: currently the idle-session
// sweep, and later the health and remediation loops.
func (p *Pool) Run(ctx context.Context) {
	p.healthMu.Lock()
	p.ctx = ctx
	p.healthMu.Unlock()

	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()
	exits := time.NewTicker(exitRefreshInterval)
	defer exits.Stop()
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
		case <-exits.C:
			p.RefreshExitNodes()
		case <-supervise.C:
			p.superviseProcesses(ctx)
		}
	}
}

// RefreshExitNodes re-reads the current exit relay of every ready instance.
//
// Failures are expected and ignored: an instance with no circuit yet simply has
// no exit to report.
func (p *Pool) RefreshExitNodes() {
	for _, inst := range p.readyInstances() {
		if _, err := inst.RefreshExitNode(); err != nil {
			p.log.Debug("exit node unavailable", "instance", inst.Index(), "error", err)
		}
	}
}

// Route returns the instance a session should use, pinning it on first sight.
//
// This is the hot path. A session keeps its instance until it rotates or the
// instance stops being routable — that stickiness is the whole point of the
// pool, so reassignment only ever happens for a reason worth logging.
func (p *Pool) Route(key string) (*tor.Instance, error) {
	now := time.Now()

	// Look up before accounting: a reassignment must not be counted as two
	// requests on the session.
	if sess, ok := p.sessions.lookup(key); ok {
		if inst, alive := p.fleet.Get(sess.Instance); alive && inst.Ready() {
			p.sessions.begin(key, now)
			return inst, nil
		}
		p.log.Info("session's instance is unavailable, reassigning",
			"session", key, "previous_instance", sess.Instance)
		p.sessions.drop(key)
	}

	inst, err := p.assign(key, now, -1)
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
func (p *Pool) Finish(key string, bytesUp, bytesDown int64, failed bool) {
	p.sessions.finish(key, bytesUp, bytesDown, failed)
	if failed {
		return
	}
	if sess, ok := p.sessions.lookup(key); ok {
		p.RecordSuccess(sess.Instance)
	}
}

// RotateSession moves a session to a different instance.
//
// Reassignment is immediate, which is the pool's main advantage over a single
// tor: NEWNYM has a 10 second cooldown, while moving to an already-built
// instance costs nothing. newnym additionally asks the vacated instance for a
// fresh circuit, which is the slow path and only worth it when the caller
// believes that exit itself is burnt.
func (p *Pool) RotateSession(ctx context.Context, key string, newnym bool) (*tor.Instance, error) {
	previous := -1
	if sess, ok := p.sessions.lookup(key); ok {
		previous = sess.Instance
	}

	inst, err := p.assign(key, time.Now(), previous)
	if err != nil {
		return nil, err
	}

	if newnym && previous >= 0 {
		if old, ok := p.fleet.Get(previous); ok {
			// Rotating the vacated instance can block on tor's cooldown, so it
			// must not hold up the caller's next request.
			go func() {
				if err := old.Newnym(ctx); err != nil && !errors.Is(err, context.Canceled) {
					p.log.Warn("newnym on vacated instance failed",
						"instance", previous, "error", err)
				}
			}()
		}
	}

	p.log.Info("session rotated", "session", key,
		"from_instance", previous, "to_instance", inst.Index(), "newnym", newnym)
	return inst, nil
}

// ReportFailure records a failure a client observed itself.
//
// This is the only signal that catches soft blocks: a 403, a 429 or a captcha
// is invisible to the balancer because it is inside an HTTPS tunnel.
func (p *Pool) ReportFailure(key, reason string) (instance int, ok bool) {
	instance, ok = p.sessions.recordFailure(key)
	if !ok {
		return 0, false
	}
	p.log.Info("client reported failure",
		"session", key, "instance", instance, "reason", reason)
	p.RecordFailure(instance, SourceClient, reason)
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
