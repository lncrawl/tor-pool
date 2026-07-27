package pool

import (
	"sync"
	"time"
)

// FailureSource says who observed a failure. The two see different things and
// neither is sufficient alone.
type FailureSource string

const (
	// SourceTransport is a failure the balancer saw itself: a refused SOCKS
	// handshake, a reset, a timeout. Free, but blind to HTTP-level blocking.
	SourceTransport FailureSource = "transport"

	// SourceClient is a failure a caller reported. The only signal that catches
	// soft blocks — a 403, a 429 or a captcha is invisible to the balancer
	// because it is inside an HTTPS tunnel.
	SourceClient FailureSource = "client"
)

// State is where an instance sits in its lifecycle.
type State string

const (
	// StateStarting covers a spawned process that has not bootstrapped.
	StateStarting State = "starting"
	// StateHealthy is routable with no recent failures.
	StateHealthy State = "healthy"
	// StateDegraded is routable but accumulating failures.
	StateDegraded State = "degraded"
	// StateProbation is routable after remediation; one more failure and it is
	// quarantined again immediately.
	StateProbation State = "probation"
	// StateQuarantined is not routable and awaiting remediation.
	StateQuarantined State = "quarantined"
	// StateRemediating is having its circuit rotated or its process restarted.
	StateRemediating State = "remediating"
)

// Rung is a step on the remediation ladder.
type Rung int

const (
	// RungNewnym asks for a fresh circuit. Cheap, and enough when only the exit
	// IP was blocked.
	RungNewnym Rung = iota
	// RungRestart wipes the DataDirectory and restarts tor, which discards
	// guards and cached consensus and produces a genuinely new identity.
	RungRestart
	// RungBackoff keeps wipe-restarting with a growing delay. In a
	// single-container topology there is nothing stronger — no separate
	// container to recreate — so the ladder honestly ends here.
	RungBackoff
)

func (r Rung) String() string {
	switch r {
	case RungNewnym:
		return "newnym"
	case RungRestart:
		return "restart"
	case RungBackoff:
		return "backoff_restart"
	default:
		return "unknown"
	}
}

// health tracks one instance's failures and remediation history.
type health struct {
	mu sync.Mutex

	state State

	// failures holds the timestamps of recent failures, oldest first. A slice
	// rather than a counter so the window can actually slide.
	failures    []time.Time
	consecutive int
	bySource    map[FailureSource]int64

	rung            Rung
	remediations    int64
	lastRemediation time.Time
	quarantinedAt   time.Time
	availableAt     time.Time
}

func newHealth() *health {
	return &health{
		state:    StateStarting,
		bySource: make(map[FailureSource]int64),
	}
}

// healthPolicy is the tuning that decides when an instance is quarantined.
type healthPolicy struct {
	Window           time.Duration
	MaxInWindow      int
	MaxConsecutive   int
	EscalationWindow time.Duration
	Backoff          time.Duration
	MaxBackoff       time.Duration
}

// recordFailure adds a failure and reports whether the instance should now be
// quarantined.
func (h *health) recordFailure(source FailureSource, now time.Time, p healthPolicy) (quarantine bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.bySource[source]++
	h.consecutive++
	h.failures = append(h.failures, now)
	h.pruneLocked(now, p.Window)

	if h.state == StateQuarantined || h.state == StateRemediating {
		return false
	}

	// On probation a single failure is decisive: the instance was just
	// remediated and is still failing, so there is nothing to wait for.
	if h.state == StateProbation {
		h.quarantineLocked(now)
		return true
	}

	if h.consecutive >= p.MaxConsecutive || len(h.failures) >= p.MaxInWindow {
		h.quarantineLocked(now)
		return true
	}

	h.state = StateDegraded
	return false
}

// recordSuccess decays the failure score.
//
// Consecutive failures reset on any success, but the windowed count does not:
// an instance failing half its requests is unhealthy even though every failure
// is followed by a success.
func (h *health) recordSuccess(now time.Time, window time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.consecutive = 0
	h.pruneLocked(now, window)

	if h.state == StateDegraded && len(h.failures) == 0 {
		h.state = StateHealthy
	}
}

func (h *health) pruneLocked(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	keep := h.failures[:0]
	for _, at := range h.failures {
		if at.After(cutoff) {
			keep = append(keep, at)
		}
	}
	h.failures = keep
}

func (h *health) quarantineLocked(now time.Time) {
	h.state = StateQuarantined
	h.quarantinedAt = now
}

// nextRung decides which remediation to apply and advances the ladder.
//
// Escalation is driven by *recurrence*, not by attempt count: an instance that
// failed once weeks ago should start again at the cheapest rung, while one
// failing repeatedly inside the escalation window has proven the cheap fix does
// not work.
func (h *health) nextRung(now time.Time, p healthPolicy) (Rung, time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	recurring := !h.lastRemediation.IsZero() && now.Sub(h.lastRemediation) < p.EscalationWindow
	switch {
	case !recurring:
		h.rung = RungNewnym
	case h.rung == RungNewnym:
		h.rung = RungRestart
	default:
		h.rung = RungBackoff
	}

	var delay time.Duration
	if h.rung == RungBackoff {
		// Exponential in the number of remediations already spent at this rung.
		delay = p.Backoff
		for range h.remediations {
			if delay >= p.MaxBackoff {
				break
			}
			delay *= 2
		}
		delay = min(delay, p.MaxBackoff)
	}

	h.state = StateRemediating
	h.remediations++
	h.lastRemediation = now
	h.availableAt = now.Add(delay)
	return h.rung, delay
}

// remediated puts the instance back into service on probation and clears the
// failure window, so the next failure is judged on fresh evidence.
func (h *health) remediated(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.state = StateProbation
	h.failures = h.failures[:0]
	h.consecutive = 0
	h.availableAt = now
}

// clearProbation promotes a probationary instance once it has proven itself.
func (h *health) clearProbation() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state == StateProbation {
		h.state = StateHealthy
	}
}

// markReady moves a starting instance into service.
func (h *health) markReady() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state == StateStarting {
		h.state = StateHealthy
	}
}

// markStarting resets state for a process that is being launched.
func (h *health) markStarting() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = StateStarting
}

// quarantine forces quarantine, for an operator acting through the API.
func (h *health) quarantine(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.quarantineLocked(now)
}

// release clears quarantine and all accumulated failures.
func (h *health) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = StateHealthy
	h.failures = h.failures[:0]
	h.consecutive = 0
	h.rung = RungNewnym
	h.availableAt = time.Time{}
}

// routable reports whether this instance may take new sessions.
func (h *health) routable(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch h.state {
	case StateHealthy, StateDegraded, StateProbation:
		return now.After(h.availableAt) || h.availableAt.IsZero()
	default:
		return false
	}
}

// snapshot returns the current health for reporting.
func (h *health) snapshot(now time.Time, window time.Duration) HealthView {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.pruneLocked(now, window)
	return HealthView{
		State:             h.state,
		FailuresInWindow:  len(h.failures),
		ConsecutiveFails:  h.consecutive,
		TransportFailures: h.bySource[SourceTransport],
		ClientFailures:    h.bySource[SourceClient],
		Remediations:      h.remediations,
		Rung:              h.rung.String(),
	}
}

// HealthView is the reportable health of an instance.
type HealthView struct {
	State             State  `json:"state"`
	FailuresInWindow  int    `json:"failures_in_window"`
	ConsecutiveFails  int    `json:"consecutive_failures"`
	TransportFailures int64  `json:"transport_failures"`
	ClientFailures    int64  `json:"client_failures"`
	Remediations      int64  `json:"remediations"`
	Rung              string `json:"remediation_rung"`
}
