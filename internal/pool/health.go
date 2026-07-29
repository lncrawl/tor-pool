package pool

import (
	"strings"
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

// FailureKind is *what* went wrong, as against FailureSource's *who saw it*.
// The two are orthogonal: a client reports a broken socket as readily as the
// balancer does, and a report's weight comes from the kind alone.
//
// Not every failure is equally damning, and treating them alike made the pool
// remediate the wrong things. A rate limit is the destination's opinion of the
// traffic volume; a captcha is its opinion of the exit IP. The vocabulary is
// deliberately small — these are the distinctions a caller can actually draw
// from inside its own HTTP client, and a longer list would only collect guesses.
type FailureKind string

const (
	// KindRateLimited is a 429 or its equivalent. The exit answered, so it works;
	// it is being asked for too much. A fresh exit IP does usually reset a
	// per-IP bucket, which is why this is not free — but it is the weakest
	// evidence there is, and spending a working exit on the first one would
	// quarantine healthy instances for doing their job.
	KindRateLimited FailureKind = "rate_limited"

	// KindBlocked is the destination refusing this exit: a 403, an IP-reputation
	// page, a block interstitial. The exit is not broken, it is unwelcome, and
	// retrying through it never becomes welcome.
	KindBlocked FailureKind = "blocked"

	// KindCaptcha is a challenge served in place of the response. The strongest
	// evidence available that the exit IP itself is burnt — and unlike a 403 it
	// is rarely path-specific — so it is weighed heavily enough to quarantine
	// well before QUARANTINE_FAILURES reports.
	KindCaptcha FailureKind = "captcha"

	// KindTransport is a connection that carried no response at all: refused,
	// reset, timed out. What the balancer sees for itself, and what a caller
	// reports when its own socket breaks.
	KindTransport FailureKind = "transport"

	// KindOther is a failure the caller could not classify, and what a bodyless
	// report counts as. Weighed as the baseline: unexplained is not harmless.
	KindOther FailureKind = "other"
)

// FailureKinds is every kind, in escalating order of what it says about the
// exit. Exported so the metrics exposition can emit a series per kind whether or
// not one has been seen — a label that appears only after the first captcha is
// one no alert can be written against.
var FailureKinds = []FailureKind{
	KindRateLimited, KindTransport, KindOther, KindBlocked, KindCaptcha,
}

// baselineWeight is what an unclassified failure scores, and the unit
// QUARANTINE_FAILURES is counted in.
//
// Scores rather than counts, so kinds can differ without QUARANTINE_FAILURES
// changing meaning: the threshold is that many *baseline* failures, so a caller
// that reports nothing but untyped failures — including one that sends no body
// at all — sees exactly the behaviour it always did.
const baselineWeight = 2

// weight is how far one report of this kind moves an instance towards
// quarantine. With the default QUARANTINE_FAILURES that is 2 captchas, 3 blocks,
// 5 transport or unclassified failures, or 10 rate limits.
//
// No single report may cross the threshold on its own, which is why this needs
// the policy. Without the ceiling the heaviest kinds collapse as
// QUARANTINE_FAILURES comes down — at 3 the captcha weight *is* the whole
// threshold, so one caller misreading one page retires an instance. An operator
// lowering it asked for fewer reports, not for a hair trigger. Setting it to 1 is
// that operator asking for exactly one report, so the ceiling lifts there.
func (k FailureKind) weight(p healthPolicy) int {
	var w int
	switch k {
	case KindRateLimited:
		w = baselineWeight / 2
	case KindBlocked:
		w = 2 * baselineWeight
	case KindCaptcha:
		w = 3 * baselineWeight
	default:
		w = baselineWeight
	}
	if ceiling := p.quarantineScore() - 1; p.MaxInWindow > 1 && w > ceiling {
		return ceiling
	}
	return w
}

// blamesExit reports whether a failure of this kind is evidence about the exit
// itself.
//
// Rate limiting is not: it follows the traffic rather than the IP, so it will
// still be there after a rotation. It must therefore stay out of the two paths
// that act on a single report — the consecutive count, and the one failure that
// re-quarantines a probationary instance — or a throttled caller would walk the
// whole ladder for an instance that was never broken.
func (k FailureKind) blamesExit() bool { return k != KindRateLimited }

// ParseFailureKind types a caller's failure report.
//
// The wire field was free text before it was typed, so the aliases matter as
// much as the canonical names: the reasons `scraper` has always sent must keep
// weighing what they mean. An unrecognised string is *not* an error — it reports
// false and the caller decides, which for the API means counting it as
// KindOther rather than throwing away the one signal that catches soft blocks
// over a spelling.
func ParseFailureKind(s string) (FailureKind, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "rate_limited", "rate_limit", "ratelimited", "throttled", "429", "http_429":
		return KindRateLimited, true
	case "blocked", "block", "forbidden", "403", "http_403":
		return KindBlocked, true
	case "captcha", "challenge":
		return KindCaptcha, true
	case "transport", "timeout", "reset", "connection_error":
		return KindTransport, true
	case "other", "unspecified":
		return KindOther, true
	default:
		return KindOther, false
	}
}

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

// failure is one scored report inside the window. The weight is stored rather
// than recomputed so ageing a failure out subtracts exactly what it added.
type failure struct {
	at     time.Time
	weight int
}

// health tracks one instance's failures and remediation history.
type health struct {
	mu sync.Mutex

	state State

	// failures holds the recent failures, oldest first. A slice rather than a
	// counter so the window can actually slide.
	failures    []failure
	consecutive int
	bySource    map[FailureSource]int64
	byKind      map[FailureKind]int64

	rung Rung
	// rungAttempts is how many remediations have been spent at the current rung,
	// which is what the backoff grows with. The lifetime count would have an
	// instance that misbehaved a lot last week start today at maximum backoff.
	rungAttempts    int
	remediations    int64
	lastRemediation time.Time
	quarantinedAt   time.Time
	availableAt     time.Time
}

func newHealth() *health {
	return &health{
		state:    StateStarting,
		bySource: make(map[FailureSource]int64),
		byKind:   make(map[FailureKind]int64),
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

// quarantineScore is the weighted score that takes an instance out of rotation:
// MaxInWindow failures of the baseline weight, or fewer of a heavier kind.
func (p healthPolicy) quarantineScore() int { return p.MaxInWindow * baselineWeight }

// recordFailure adds a failure and reports whether the instance should now be
// quarantined.
//
// The kind is what decides how much this one report counts. A captcha crosses
// the threshold in two reports where an unclassified failure needs
// QUARANTINE_FAILURES of them, and a rate limit — which says the exit works and
// is merely busy — neither trips the consecutive count nor re-quarantines an
// instance on probation.
//
// The weighing governs one of the two triggers. MaxConsecutive is blind to kind
// and still caps every report that blames the exit, so a caller failing without
// a success in between quarantines the instance there first, whatever it reports
// — which is why excluding rate limits from that count matters more than their
// weight does.
func (h *health) recordFailure(source FailureSource, kind FailureKind, now time.Time, p healthPolicy) (quarantine bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.bySource[source]++
	h.byKind[kind]++
	if kind.blamesExit() {
		h.consecutive++
	}
	h.failures = append(h.failures, failure{at: now, weight: kind.weight(p)})
	h.pruneLocked(now, p.Window)

	if h.state == StateQuarantined || h.state == StateRemediating {
		return false
	}

	// On probation a single failure is decisive: the instance was just
	// remediated and is still failing, so there is nothing to wait for.
	if h.state == StateProbation {
		if !kind.blamesExit() {
			// A rate limit is not evidence the remediation failed. Falling through
			// would also drop the instance to degraded, which spends a probation it
			// has not yet earned its way out of — the *next* report would then need
			// the full threshold instead of being decisive.
			return false
		}
		h.quarantineLocked(now)
		return true
	}

	if h.consecutive >= p.MaxConsecutive || h.scoreLocked() >= p.quarantineScore() {
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
	for _, f := range h.failures {
		if f.at.After(cutoff) {
			keep = append(keep, f)
		}
	}
	h.failures = keep
}

// scoreLocked totals the weight of the failures still inside the window.
func (h *health) scoreLocked() int {
	var score int
	for _, f := range h.failures {
		score += f.weight
	}
	return score
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
	previous := h.rung
	switch {
	case !recurring:
		h.rung = RungNewnym
	case h.rung == RungNewnym:
		h.rung = RungRestart
	default:
		h.rung = RungBackoff
	}
	if h.rung != previous || !recurring {
		h.rungAttempts = 0
	}

	var delay time.Duration
	if h.rung == RungBackoff {
		// Exponential in the number of remediations already spent at this rung.
		delay = p.Backoff
		for range h.rungAttempts {
			if delay >= p.MaxBackoff {
				break
			}
			delay *= 2
		}
		delay = min(delay, p.MaxBackoff)
	}

	h.state = StateRemediating
	h.rungAttempts++
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
	h.rungAttempts = 0
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
//
// It takes the whole policy rather than just the window because the score alone
// says nothing: a reader needs the threshold it is measured against, and
// deriving that from QUARANTINE_FAILURES outside this file would put the weight
// unit in two places.
func (h *health) snapshot(now time.Time, policy healthPolicy) HealthView {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.pruneLocked(now, policy.Window)

	// Copied, not shared: the caller reads this map after the lock is gone, and
	// the next report would write to it underneath them.
	byKind := make(map[FailureKind]int64, len(h.byKind))
	for kind, n := range h.byKind {
		byKind[kind] = n
	}

	return HealthView{
		State:             h.state,
		FailuresInWindow:  len(h.failures),
		FailureScore:      h.scoreLocked(),
		QuarantineScore:   policy.quarantineScore(),
		ConsecutiveFails:  h.consecutive,
		TransportFailures: h.bySource[SourceTransport],
		ClientFailures:    h.bySource[SourceClient],
		FailuresByKind:    byKind,
		Remediations:      h.remediations,
		Rung:              h.rung.String(),
	}
}

// HealthView is the reportable health of an instance.
type HealthView struct {
	State State `json:"state"`
	// FailuresInWindow counts reports; FailureScore weighs them by kind, and is
	// what QuarantineScore is compared against. Both are reported because a
	// consumer cannot derive either from the other, and the ratio that matters —
	// how close this instance is to being quarantined — is the scored one.
	FailuresInWindow  int                   `json:"failures_in_window"`
	FailureScore      int                   `json:"failure_score"`
	QuarantineScore   int                   `json:"quarantine_score"`
	ConsecutiveFails  int                   `json:"consecutive_failures"`
	TransportFailures int64                 `json:"transport_failures"`
	ClientFailures    int64                 `json:"client_failures"`
	FailuresByKind    map[FailureKind]int64 `json:"failures_by_kind"`
	Remediations      int64                 `json:"remediations"`
	Rung              string                `json:"remediation_rung"`
}
