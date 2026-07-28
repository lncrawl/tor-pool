// Package server exposes the pool over HTTP: a REST API, an SSE stream for
// live updates, Prometheus metrics, and the embedded dashboard.
//
// There is no authentication. The API can restart instances and resize the
// pool, so the container must publish this port to loopback only.
package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/pool"
	"github.com/lncrawl/tor-pool/internal/stats"
)

// errNoSuchInstance is returned for an action addressed to a retired instance.
var errNoSuchInstance = errors.New("no such instance")

// Server serves the API and dashboard.
type Server struct {
	pool    *pool.Pool
	cfg     *config.Config
	log     *slog.Logger
	version string
}

// New builds the HTTP surface over a pool.
func New(p *pool.Pool, cfg *config.Config, version string, log *slog.Logger) *Server {
	return &Server{pool: p, cfg: cfg, log: log, version: version}
}

// Handler returns the fully routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	mux.HandleFunc("GET /api/pool", s.handlePool)
	mux.HandleFunc("POST /api/pool/rotate", s.handlePoolRotate)
	mux.HandleFunc("POST /api/pool/resize", s.handlePoolResize)

	mux.HandleFunc("GET /api/instances", s.handleInstances)
	mux.HandleFunc("GET /api/instances/{id}", s.handleInstance)
	mux.HandleFunc("POST /api/instances/{id}/rotate", s.instanceAction(
		func(_ *http.Request, id int) error { return s.pool.RotateInstance(id) }))
	mux.HandleFunc("POST /api/instances/{id}/restart", s.instanceAction(
		func(r *http.Request, id int) error {
			// Wiping is the default: a restart that keeps its guards and cached
			// consensus is rarely what an operator means by "restart this".
			return s.pool.RestartInstance(id, r.URL.Query().Get("wipe") != "false")
		}))
	mux.HandleFunc("POST /api/instances/{id}/quarantine", s.instanceAction(
		func(_ *http.Request, id int) error { return boolErr(s.pool.QuarantineInstance(id)) }))
	mux.HandleFunc("POST /api/instances/{id}/release", s.instanceAction(
		func(_ *http.Request, id int) error { return boolErr(s.pool.ReleaseInstance(id)) }))
	mux.HandleFunc("POST /api/instances/{id}/drain", s.handleDrain)

	mux.HandleFunc("GET /api/sessions", s.handleSessions)
	mux.HandleFunc("GET /api/sessions/{key}", s.handleSession)
	mux.HandleFunc("POST /api/sessions/{key}/rotate", s.handleSessionRotate)
	mux.HandleFunc("POST /api/sessions/{key}/failure", s.handleSessionFailure)
	mux.HandleFunc("DELETE /api/sessions/{key}", s.handleSessionDrop)

	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/stats/history", s.handleHistory)
	mux.HandleFunc("GET /api/stream", s.handleStream)

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
	writeJSON(w, map[string]any{"rotating": s.pool.RotateAll()})
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
	RetiredExitIP string               `json:"retired_exit_ip"`
	Health        pool.HealthView      `json:"health"`
	Totals        stats.InstanceTotals `json:"totals"`
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
			if errors.Is(err, errNoSuchInstance) {
				status = http.StatusNotFound
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
	newnym := r.URL.Query().Get("newnym") == "true"

	inst, err := s.pool.RotateSession(key, newnym)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Read the new instance's exit now rather than serving a value cached from
	// before the move. It is still a best guess until traffic flows: no stream
	// is attached to this session yet, so tor has not committed to a circuit.
	node, err := inst.RefreshExitNode()
	if err != nil {
		node = inst.ExitNode()
	}
	writeJSON(w, map[string]any{
		"session":  key,
		"instance": inst.Index(),
		"exit_ip":  node.Address,
	})
}

func (s *Server) handleSessionFailure(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	var body struct {
		Reason string `json:"reason"`
	}
	// A failure report with no body is still a valid signal.
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Reason == "" {
		body.Reason = "unspecified"
	}

	instance, ok := s.pool.ReportFailure(key, body.Reason)
	if !ok {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"session": key, "instance": instance})
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
