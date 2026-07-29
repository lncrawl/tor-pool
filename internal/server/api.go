// Package server exposes the pool over HTTP: a REST API, an SSE stream for
// live updates, Prometheus metrics, and the embedded dashboard.
//
// Everything under /api/ requires a credential; /health, /metrics, the login and
// status endpoints and the dashboard's static assets do not. Authentication is a
// Bearer header and never a cookie, which is what makes the mutating endpoints
// immune to cross-site requests — there is no CSRF defence here, and none is
// needed as long as that holds.
//
// AUTH_DISABLED removes the requirement everywhere at once. The route table still
// declares a scope for every endpoint and the guard still runs; it is
// internal/auth that stops refusing, so there is no second, unguarded code path
// that could drift out of step with this one.
//
// It is still not a substitute for TLS. Passwords, JWTs and tokens all cross the
// wire in cleartext, so publishing this port beyond loopback needs something in
// front of it.
package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/lncrawl/tor-pool/internal/auth"
	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/pool"
	"github.com/lncrawl/tor-pool/internal/stats"
)

// errNoSuchInstance is returned for an action addressed to a retired instance.
//
// It aliases the pool's sentinel rather than declaring a second error with the
// same text: the existence check here and the one inside the pool race with a
// resize, and a distinct value would make the loser of that race a 500.
var errNoSuchInstance = pool.ErrNoSuchInstance

// Server serves the API and dashboard.
type Server struct {
	pool    *pool.Pool
	auth    *auth.Auth
	cfg     *config.Config
	log     *slog.Logger
	version string
}

// New builds the HTTP surface over a pool.
func New(p *pool.Pool, credentials *auth.Auth, cfg *config.Config, version string, log *slog.Logger) *Server {
	return &Server{pool: p, auth: credentials, cfg: cfg, log: log, version: version}
}

// route is one endpoint and the scope a caller needs for it.
type route struct {
	// method is empty for a pattern that answers every method.
	method string
	path   string
	// need is the scope required. Empty means public, and only /health,
	// /metrics and the login endpoint may be.
	need auth.Scope
	// ticket lets the credential arrive as a query parameter instead of a
	// header, because EventSource cannot send one. Only the stream sets it.
	ticket  bool
	handler http.HandlerFunc
}

// routes is the API surface as data.
//
// A table rather than twenty HandleFunc calls, because that is what makes
// authentication default-closed: a new endpoint cannot exist without naming a
// scope, and TestEveryRouteIsGuarded walks this very slice to prove none was
// forgotten. http.ServeMux does not expose the patterns it was given, so a test
// has no other way to discover them.
func (s *Server) routes() []route {
	return []route{
		// Public. /health is probed by the container healthcheck and by CI, and
		// /metrics by scrapers that assume a trusted network. The login endpoint
		// has to be reachable by definition; it is rate limited instead.
		{method: "GET", path: "/health", handler: s.handleHealth},
		{method: "GET", path: "/metrics", handler: s.handleMetrics},
		{method: "POST", path: "/api/auth/login", handler: s.handleLogin},
		// Public because the dashboard has to know whether to render a sign-in
		// screen before it has anything to sign in with. It leaks nothing: the
		// same answer falls out of any request, as a 401 or a 200.
		{method: "GET", path: "/api/auth/status", handler: s.handleAuthStatus},

		{method: "POST", path: "/api/auth/ticket", need: auth.ScopeAdmin, handler: s.handleTicket},

		{method: "GET", path: "/api/tokens", need: auth.ScopeAdmin, handler: s.handleTokens},
		{method: "POST", path: "/api/tokens", need: auth.ScopeAdmin, handler: s.handleMintToken},
		{method: "DELETE", path: "/api/tokens/{id}", need: auth.ScopeAdmin, handler: s.handleRevokeToken},

		{method: "GET", path: "/api/pool", need: auth.ScopeAdmin, handler: s.handlePool},
		{method: "POST", path: "/api/pool/rotate", need: auth.ScopeAdmin, handler: s.handlePoolRotate},
		{method: "POST", path: "/api/pool/resize", need: auth.ScopeAdmin, handler: s.handlePoolResize},

		{method: "GET", path: "/api/instances", need: auth.ScopeAdmin, handler: s.handleInstances},
		{method: "GET", path: "/api/instances/{id}", need: auth.ScopeAdmin, handler: s.handleInstance},
		{method: "POST", path: "/api/instances/{id}/rotate", need: auth.ScopeAdmin, handler: s.instanceAction(
			// Started, not awaited: the instance stops taking traffic and its
			// sessions move before this returns, and what is left is tor's NEWNYM
			// cooldown — up to ten seconds of nothing worth holding a request open
			// for. The dashboard sees the new exit arrive over the SSE stream.
			func(_ *http.Request, id int) error { return s.pool.StartRotateInstance(id) })},
		{method: "POST", path: "/api/instances/{id}/restart", need: auth.ScopeAdmin, handler: s.instanceAction(
			func(r *http.Request, id int) error {
				// Wiping is the default: a restart that keeps its guards and cached
				// consensus is rarely what an operator means by "restart this".
				return s.pool.RestartInstance(id, r.URL.Query().Get("wipe") != "false")
			})},
		{method: "POST", path: "/api/instances/{id}/quarantine", need: auth.ScopeAdmin, handler: s.instanceAction(
			func(_ *http.Request, id int) error { return boolErr(s.pool.QuarantineInstance(id)) })},
		{method: "POST", path: "/api/instances/{id}/release", need: auth.ScopeAdmin, handler: s.instanceAction(
			func(_ *http.Request, id int) error { return boolErr(s.pool.ReleaseInstance(id)) })},
		{method: "POST", path: "/api/instances/{id}/drain", need: auth.ScopeAdmin, handler: s.handleDrain},

		// Rotating, reporting a failure and releasing are the data plane's own
		// control surface: the scraper calls them with the token it already holds.
		// Under the admin scope, that token could also resize the pool and restart
		// instances, so these stay narrow. Listing every session is still an
		// operator view — one caller has no business enumerating the others.
		//
		// DELETE is on the proxy scope because a client releasing the session it
		// created is housekeeping, not administration, and requiring admin for it
		// meant no client could ever do it. They then accumulated until
		// SESSION_TTL, and a caller that opened several in a row exhausted the
		// pool — which surfaces downstream as a connection failure and gets
		// blamed on the destination rather than on the leak. A key is an identity
		// hint and not a boundary (see internal/pool/sessions.go), so this does
		// not stop one caller dropping another's; every token is the same
		// operator's, and the alternative was a guaranteed leak.
		{method: "GET", path: "/api/sessions", need: auth.ScopeAdmin, handler: s.handleSessions},
		{method: "GET", path: "/api/sessions/{key}", need: auth.ScopeProxy, handler: s.handleSession},
		{method: "POST", path: "/api/sessions/{key}/rotate", need: auth.ScopeProxy, handler: s.handleSessionRotate},
		{method: "POST", path: "/api/sessions/{key}/failure", need: auth.ScopeProxy, handler: s.handleSessionFailure},
		{method: "DELETE", path: "/api/sessions/{key}", need: auth.ScopeProxy, handler: s.handleSessionDrop},

		{method: "GET", path: "/api/events", need: auth.ScopeAdmin, handler: s.handleEvents},
		{method: "GET", path: "/api/stats/history", need: auth.ScopeAdmin, handler: s.handleHistory},
		{method: "GET", path: "/api/stream", need: auth.ScopeAdmin, ticket: true, handler: s.handleStream},

		// Anything else under /api/ is authenticated before it is answered, so
		// the surface does not leak which endpoints exist. ServeMux ranks this
		// subtree pattern below every specific one above.
		{path: "/api/", need: auth.ScopeAdmin, handler: http.NotFound},
	}
}

// Handler returns the fully routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		pattern := rt.path
		if rt.method != "" {
			pattern = rt.method + " " + rt.path
		}
		mux.HandleFunc(pattern, s.guard(rt))
	}
	s.mountDashboard(mux)
	return mux
}

func boolErr(ok bool) error {
	if !ok {
		return errNoSuchInstance
	}
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	// Routable, not merely bootstrapped: an all-quarantined pool is alive but
	// cannot serve a single request, and must say so.
	if s.pool.RoutableCount() == 0 {
		http.Error(w, "no routable instances", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// PoolView is the pool summary.
type PoolView struct {
	Version   string       `json:"version"`
	Size      int          `json:"size"`
	Ready     int          `json:"ready"`
	Routable  int          `json:"routable"`
	Sessions  int          `json:"sessions"`
	Totals    stats.Totals `json:"totals"`
	SocksPort int          `json:"socks_port"`
	HTTPPort  int          `json:"http_port"`
	Config    PoolConfig   `json:"config"`
}

// PoolConfig is the subset of configuration worth showing in the UI.
type PoolConfig struct {
	PoolSize              int    `json:"pool_size"`
	SessionTTL            string `json:"session_ttl"`
	DefaultSession        string `json:"default_session"`
	FailureWindow         string `json:"failure_window"`
	QuarantineFailures    int    `json:"quarantine_failures"`
	QuarantineConsecutive int    `json:"quarantine_consecutive"`
	MaxCircuitDirtiness   string `json:"max_circuit_dirtiness"`
}

func (s *Server) poolView() PoolView {
	fleet := s.pool.Fleet()
	return PoolView{
		Version:   s.version,
		Size:      fleet.Size(),
		Ready:     fleet.ReadyCount(),
		Routable:  s.pool.RoutableCount(),
		Sessions:  s.pool.SessionCount(),
		Totals:    s.pool.Stats().Totals(),
		SocksPort: s.cfg.SocksPort,
		HTTPPort:  s.cfg.HTTPPort,
		Config: PoolConfig{
			PoolSize:              s.cfg.PoolSize,
			SessionTTL:            s.cfg.SessionTTL.String(),
			DefaultSession:        string(s.cfg.DefaultSession),
			FailureWindow:         s.cfg.FailureWindow.String(),
			QuarantineFailures:    s.cfg.QuarantineFailures,
			QuarantineConsecutive: s.cfg.QuarantineConsecutive,
			MaxCircuitDirtiness:   s.cfg.MaxCircuitDirtiness.String(),
		},
	}
}

func (s *Server) handlePool(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.poolView())
}

func (s *Server) handlePoolRotate(w http.ResponseWriter, _ *http.Request) {
	queued, alreadyRunning := s.pool.RotateAll()
	writeJSON(w, map[string]any{
		"rotating": queued,
		// The sweep is serial so the pool keeps serving, which means it outlives
		// this request by roughly tor's cooldown per instance. Saying so is the
		// difference between "nothing happened" and "it is already happening".
		"in_progress": alreadyRunning,
	})
}

func (s *Server) handlePoolResize(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Size int `json:"size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `body must be {"size": N}`, http.StatusBadRequest)
		return
	}
	if err := s.pool.Resize(body.Size); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"size": s.pool.Fleet().Size()})
}

// InstanceView is one instance as the API reports it.
type InstanceView struct {
	ID          int    `json:"id"`
	Ready       bool   `json:"ready"`
	Running     bool   `json:"running"`
	Bootstrap   int    `json:"bootstrap"`
	Pid         int    `json:"pid"`
	UptimeSecs  int    `json:"uptime_secs"`
	Sessions    int    `json:"sessions"`
	SocksAddr   string `json:"socks_addr"`
	ExitIP      string `json:"exit_ip"`
	ExitCountry string `json:"exit_country"`
	ExitNick    string `json:"exit_nickname"`
	// RetiredExitIP is set only while ExitIP is empty: a rotation discarded that
	// exit and tor has not committed to a replacement, which for an idle
	// instance lasts until its next request.
	RetiredExitIP string `json:"retired_exit_ip"`
	// ExitConfirmed says whether traffic has actually left through ExitIP. When
	// false it is inferred from the circuits tor is holding, several of which it
	// built preemptively and no request may ever use.
	ExitConfirmed bool `json:"exit_confirmed"`
	// PinnedExit is the relay this instance is locked to, when PIN_EXIT_RELAY is
	// on. Empty means tor is choosing exits for itself.
	PinnedExit string               `json:"pinned_exit"`
	Health     pool.HealthView      `json:"health"`
	Totals     stats.InstanceTotals `json:"totals"`
}

func (s *Server) instanceViews() []InstanceView {
	instances := s.pool.Fleet().Instances()
	counts := s.pool.SessionsPerInstance()
	health := s.pool.Health()
	collector := s.pool.Stats()

	out := make([]InstanceView, 0, len(instances))
	for _, inst := range instances {
		// The exit cache is kept current by the pool's refresh loop and by
		// sampling during live connections; reading it here keeps API latency
		// off the control port.
		node := inst.ExitNode()
		id := inst.Index()
		out = append(out, InstanceView{
			ID:            id,
			Ready:         inst.Ready(),
			Running:       inst.Running(),
			Bootstrap:     inst.Bootstrap(),
			Pid:           inst.Pid(),
			UptimeSecs:    int(time.Since(inst.StartedAt()).Seconds()),
			Sessions:      counts[id],
			SocksAddr:     inst.Config().SocksAddr(),
			ExitIP:        node.Address,
			ExitCountry:   node.Country,
			ExitNick:      node.Nickname,
			RetiredExitIP: inst.RetiredExit().Address,
			ExitConfirmed: inst.ExitConfirmed(),
			PinnedExit:    inst.PinnedExit(),
			Health:        health[id],
			Totals:        collector.Instance(id),
		})
	}
	return out
}

func (s *Server) handleInstances(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.instanceViews())
}

func (s *Server) handleInstance(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "instance id must be a number", http.StatusBadRequest)
		return
	}
	views := s.instanceViews()
	for i := range views {
		if views[i].ID == id {
			writeJSON(w, views[i])
			return
		}
	}
	http.Error(w, errNoSuchInstance.Error(), http.StatusNotFound)
}

// instanceAction wraps the plumbing shared by the per-instance endpoints.
func (s *Server) instanceAction(act func(*http.Request, int) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, "instance id must be a number", http.StatusBadRequest)
			return
		}
		if _, ok := s.pool.Fleet().Get(id); !ok {
			http.Error(w, errNoSuchInstance.Error(), http.StatusNotFound)
			return
		}

		if err := act(r, id); err != nil {
			status := http.StatusInternalServerError
			switch {
			case errors.Is(err, errNoSuchInstance):
				status = http.StatusNotFound
			case errors.Is(err, pool.ErrInstanceNotReady):
				// The request is well formed and the instance exists; it is the
				// state that makes the action impossible, and it will not be
				// impossible for long.
				status = http.StatusConflict
			}
			http.Error(w, err.Error(), status)
			return
		}

		inst, ok := s.pool.Fleet().Get(id)
		if !ok {
			writeJSON(w, map[string]any{"instance": id})
			return
		}
		writeJSON(w, map[string]any{
			"instance": id,
			"state":    s.pool.Health()[id].State,
			"exit_ip":  inst.ExitNode().Address,
		})
	}
}

func (s *Server) handleDrain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "instance id must be a number", http.StatusBadRequest)
		return
	}
	if _, ok := s.pool.Fleet().Get(id); !ok {
		http.Error(w, errNoSuchInstance.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"instance": id, "sessions_moved": s.pool.DrainInstance(id)})
}

func (s *Server) handleSessions(w http.ResponseWriter, _ *http.Request) {
	sessions := s.pool.Sessions()
	if sessions == nil {
		sessions = []pool.Session{}
	}
	writeJSON(w, sessions)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.pool.Session(r.PathValue("key"))
	if !ok {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	writeJSON(w, sess)
}

func (s *Server) handleSessionRotate(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	// A flag is a flag: "1", "yes" and "on" all clearly mean the same thing as
	// "true", and silently ignoring them made rotation look like it had no
	// newnym option at all.
	newnym, _ := strconv.ParseBool(r.URL.Query().Get("newnym"))

	inst, err := s.pool.RotateSession(key, newnym)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{
		"session":  key,
		"instance": inst.Index(),
		// Whatever the instance last confirmed. Deliberately not re-read here:
		// no stream of this session is attached yet, so a fresh read would only
		// name whichever circuit tor happens to be holding — which is exactly
		// the guess that made a rotation look like it landed on one IP and then
		// moved to another.
		"exit_ip":        inst.ExitNode().Address,
		"exit_confirmed": inst.ExitConfirmed(),
	})
}

// handleSessionFailure records a failure a caller observed, typed by what it
// says about the exit.
//
// The kind is the whole point of the endpoint: a 429 means the exit works and is
// busy, a captcha means it is burnt, and weighing them alike had the pool
// quarantine throttled-but-healthy instances while a challenged one stayed in
// rotation for four more reports. See pool.FailureKind.
//
// Every shape of report is accepted, in this order of preference:
//
//	{"kind": "captcha", "reason": "cf challenge on /search"}  typed, with detail
//	{"reason": "http_403"}                                    classified from text
//	(no body at all)                                          counted as "other"
//
// A bodyless POST is the documented minimum signal and stays exactly that. Text
// that types to nothing known is counted as pool.KindOther rather than refused:
// the report is still evidence, and answering 400 would discard the only signal
// that catches soft blocks over a spelling.
func (s *Server) handleSessionFailure(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	var body struct {
		Kind string `json:"kind"`
		// Reason stays free text for the audit log, and is what the report is
		// typed from when Kind is absent — it was the only field before kinds
		// existed, and every deployed caller sends it.
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	kind := classifyFailure(body.Kind, body.Reason)
	reason := body.Reason
	if reason == "" {
		reason = body.Kind
	}

	instance, ok := s.pool.ReportFailure(key, kind, reason)
	if !ok {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	// The kind is echoed back because a caller has no other way to see how its
	// text was read, and how much the report counted for depends entirely on it.
	writeJSON(w, map[string]any{"session": key, "instance": instance, "kind": kind})
}

// classifyFailure types a report from the two fields a caller may send.
//
// An explicit kind wins, then the free-text reason, and anything neither field
// types is KindOther — including a kind that is simply misspelled, which then
// still gets a chance to be read from the reason.
func classifyFailure(kind, reason string) pool.FailureKind {
	for _, text := range []string{kind, reason} {
		if k, known := pool.ParseFailureKind(text); known {
			return k
		}
	}
	return pool.KindOther
}

func (s *Server) handleSessionDrop(w http.ResponseWriter, r *http.Request) {
	if !s.pool.DropSession(r.PathValue("key")) {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	events := s.pool.Events().Recent(limit)
	if events == nil {
		events = []stats.Event{}
	}
	writeJSON(w, events)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	// The coarse series trades resolution for reach, so the dashboard can zoom
	// out without the pool retaining hours at one-second granularity.
	coarse := r.URL.Query().Get("range") == "long"
	series := s.pool.Stats().History(coarse)
	if series == nil {
		series = []stats.Sample{}
	}
	writeJSON(w, series)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("write json response", "error", err)
	}
}
