// Command torpool runs a pool of tor instances behind a single sticky proxy
// endpoint, with a REST API and dashboard for managing them.
//
// It is designed to be PID 1 in its container: it owns the tor child processes
// and must shut them down itself, since nothing else will reap them.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/pool"
	"github.com/lncrawl/tor-pool/internal/proxy"
	"github.com/lncrawl/tor-pool/internal/tor"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

// shutdownGrace bounds how long the HTTP server gets to drain before the
// process exits. Tor children get their own grace period on top of this.
const shutdownGrace = 5 * time.Second

func main() {
	if err := run(); err != nil {
		// slog may not be configured yet if config parsing failed, so report
		// to stderr directly.
		fmt.Fprintf(os.Stderr, "torpool: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}

	log := newLogger(cfg.LogLevel)
	log.Info("starting torpool",
		"version", version,
		"pool_size", cfg.PoolSize,
		"socks_port", cfg.SocksPort,
		"http_port", cfg.HTTPPort,
		"api_port", cfg.APIPort,
	)

	// Notify-based cancellation rather than a signal goroutine: SIGTERM from
	// `docker stop` must reach the tor children through ctx, not race with them.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fleet := tor.NewFleet(tor.FleetOptions{
		Size:                cfg.PoolSize,
		Binary:              cfg.TorBinary,
		DataDir:             cfg.DataDir,
		SocksPortFor:        cfg.InstanceSocksPort,
		ControlPortFor:      cfg.InstanceControlPort,
		SpawnStagger:        cfg.SpawnStagger,
		MinReady:            cfg.MinReady,
		ExitNodes:           cfg.ExitNodes,
		ExcludeExitNodes:    cfg.ExcludeExitNodes,
		StrictNodes:         cfg.StrictNodes,
		MaxCircuitDirtiness: cfg.MaxCircuitDirtiness,
		ExtraTorConfig:      cfg.ExtraTorConfig,
	}, log)

	// Stopping the fleet is the last thing to happen: the API must stay up
	// while instances drain so a shutdown is observable.
	defer func() {
		if err := fleet.Stop(); err != nil {
			log.Error("fleet shutdown", "error", err)
		}
		log.Info("all instances stopped")
	}()

	p := pool.New(&cfg, fleet, log)
	go p.Run(ctx)

	proxies := proxy.NewServer(&cfg, p, log)
	if err := proxies.Start(ctx); err != nil {
		return fmt.Errorf("start proxy listeners: %w", err)
	}
	defer func() {
		if err := proxies.Close(); err != nil {
			log.Error("proxy shutdown", "error", err)
		}
	}()

	srv := &http.Server{
		Addr:              net.JoinHostPort(cfg.BindHost, strconv.Itoa(cfg.APIPort)),
		Handler:           statusHandler(p, &cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info("api listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("api server", "error", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("api shutdown", "error", err)
		}
	}()

	if err := fleet.Start(ctx); err != nil {
		return fmt.Errorf("start pool: %w", err)
	}
	log.Info("pool is ready", "ready", fleet.ReadyCount(), "size", fleet.Size())

	<-ctx.Done()
	log.Info("shutdown signal received")
	return nil
}

// statusHandler is the interim API: enough to observe and drive the pool from
// the command line. The full REST surface, SSE stream and dashboard replace it.
func statusHandler(p *pool.Pool, cfg *config.Config) http.Handler {
	mux := http.NewServeMux()
	fleet := p.Fleet()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		// Routable, not merely bootstrapped: an all-quarantined pool is alive
		// but cannot serve a single request, and must say so.
		if p.RoutableCount() == 0 {
			http.Error(w, "no routable instances", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /api/instances", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, instanceViews(p))
	})

	mux.HandleFunc("GET /api/pool", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"version":    version,
			"size":       fleet.Size(),
			"ready":      fleet.ReadyCount(),
			"routable":   p.RoutableCount(),
			"sessions":   p.SessionCount(),
			"pool_size":  cfg.PoolSize,
			"socks_port": cfg.SocksPort,
			"http_port":  cfg.HTTPPort,
		})
	})

	mux.HandleFunc("POST /api/instances/{id}/rotate", instanceAction(p,
		func(r *http.Request, id int) error { return p.RotateInstance(r.Context(), id) }))

	mux.HandleFunc("POST /api/instances/{id}/restart", instanceAction(p,
		func(r *http.Request, id int) error {
			// Wiping is the default: a restart that keeps its guards and cached
			// consensus is rarely what an operator means by "restart this".
			wipe := r.URL.Query().Get("wipe") != "false"
			return p.RestartInstance(r.Context(), id, wipe)
		}))

	mux.HandleFunc("POST /api/instances/{id}/quarantine", instanceAction(p,
		func(_ *http.Request, id int) error {
			if !p.QuarantineInstance(id) {
				return errNoSuchInstance
			}
			return nil
		}))

	mux.HandleFunc("POST /api/instances/{id}/release", instanceAction(p,
		func(_ *http.Request, id int) error {
			if !p.ReleaseInstance(id) {
				return errNoSuchInstance
			}
			return nil
		}))

	mux.HandleFunc("POST /api/instances/{id}/drain", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, "instance id must be a number", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"instance": id, "sessions_moved": p.DrainInstance(id)})
	})

	mux.HandleFunc("POST /api/pool/rotate", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"rotating": p.RotateAll(r.Context())})
	})

	mux.HandleFunc("POST /api/pool/resize", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Size int `json:"size"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "body must be {\"size\": N}", http.StatusBadRequest)
			return
		}
		if err := p.Resize(r.Context(), body.Size); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"size": p.Fleet().Size()})
	})

	mux.HandleFunc("GET /api/sessions", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, p.Sessions())
	})

	mux.HandleFunc("GET /api/sessions/{key}", func(w http.ResponseWriter, r *http.Request) {
		sess, ok := p.Session(r.PathValue("key"))
		if !ok {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		writeJSON(w, sess)
	})

	mux.HandleFunc("POST /api/sessions/{key}/rotate", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")
		newnym := r.URL.Query().Get("newnym") == "true"

		inst, err := p.RotateSession(r.Context(), key, newnym)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		// Read the new instance's exit now rather than serving a cached value
		// from before the move. It is still a best guess until traffic actually
		// flows: no stream is attached to this session yet, so tor has not
		// committed to a circuit for it.
		node, err := inst.RefreshExitNode()
		if err != nil {
			node = inst.ExitNode()
		}
		writeJSON(w, map[string]any{
			"session":  key,
			"instance": inst.Index(),
			"exit_ip":  node.Address,
		})
	})

	mux.HandleFunc("POST /api/sessions/{key}/failure", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")

		var body struct {
			Reason string `json:"reason"`
		}
		// A failure report with no body is still a valid signal.
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Reason == "" {
			body.Reason = "unspecified"
		}

		instance, ok := p.ReportFailure(key, body.Reason)
		if !ok {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"session": key, "instance": instance})
	})

	mux.HandleFunc("DELETE /api/sessions/{key}", func(w http.ResponseWriter, r *http.Request) {
		if !p.DropSession(r.PathValue("key")) {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}

// errNoSuchInstance is returned by an action addressed to an instance that has
// been retired.
var errNoSuchInstance = errors.New("no such instance")

// instanceAction wraps the shared plumbing of the per-instance endpoints:
// parsing the id, running the action, and reporting the instance's resulting
// state.
func instanceAction(p *pool.Pool, act func(*http.Request, int) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, "instance id must be a number", http.StatusBadRequest)
			return
		}
		if _, ok := p.Fleet().Get(id); !ok {
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

		inst, ok := p.Fleet().Get(id)
		if !ok {
			// A restart can retire and replace the instance underneath us.
			writeJSON(w, map[string]any{"instance": id})
			return
		}
		writeJSON(w, map[string]any{
			"instance": id,
			"state":    p.Health()[id].State,
			"exit_ip":  inst.ExitNode().Address,
		})
	}
}

// instanceView is the interim JSON shape for an instance.
type instanceView struct {
	ID          int             `json:"id"`
	Ready       bool            `json:"ready"`
	Running     bool            `json:"running"`
	Bootstrap   int             `json:"bootstrap"`
	Pid         int             `json:"pid"`
	UptimeSecs  int             `json:"uptime_secs"`
	Sessions    int             `json:"sessions"`
	SocksAddr   string          `json:"socks_addr"`
	ExitIP      string          `json:"exit_ip"`
	ExitCountry string          `json:"exit_country"`
	ExitNick    string          `json:"exit_nickname"`
	Health      pool.HealthView `json:"health"`
}

func instanceViews(p *pool.Pool) []instanceView {
	instances := p.Fleet().Instances()
	counts := p.SessionsPerInstance()
	healthByID := p.Health()

	out := make([]instanceView, 0, len(instances))
	for _, inst := range instances {
		// The cache is kept current by the pool's refresh loop; reading it here
		// keeps API latency off the control port.
		node := inst.ExitNode()
		out = append(out, instanceView{
			ID:          inst.Index(),
			Ready:       inst.Ready(),
			Running:     inst.Running(),
			Bootstrap:   inst.Bootstrap(),
			Pid:         inst.Pid(),
			UptimeSecs:  int(time.Since(inst.StartedAt()).Seconds()),
			Sessions:    counts[inst.Index()],
			SocksAddr:   inst.Config().SocksAddr(),
			ExitIP:      node.Address,
			ExitCountry: node.Country,
			ExitNick:    node.Nickname,
			Health:      healthByID[inst.Index()],
		})
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("write json response", "error", err)
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)
	return log
}
