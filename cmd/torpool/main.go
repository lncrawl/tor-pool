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
		Size:             cfg.PoolSize,
		Binary:           cfg.TorBinary,
		DataDir:          cfg.DataDir,
		SocksPortFor:     cfg.InstanceSocksPort,
		ControlPortFor:   cfg.InstanceControlPort,
		SpawnStagger:     cfg.SpawnStagger,
		MinReady:         cfg.MinReady,
		ExitNodes:        cfg.ExitNodes,
		ExcludeExitNodes: cfg.ExcludeExitNodes,
		StrictNodes:      cfg.StrictNodes,
		ExtraTorConfig:   cfg.ExtraTorConfig,
	}, log)

	// Stopping the fleet is the last thing to happen: the API must stay up
	// while instances drain so a shutdown is observable.
	defer func() {
		if err := fleet.Stop(); err != nil {
			log.Error("fleet shutdown", "error", err)
		}
		log.Info("all instances stopped")
	}()

	srv := &http.Server{
		Addr:              net.JoinHostPort(cfg.BindHost, strconv.Itoa(cfg.APIPort)),
		Handler:           statusHandler(fleet, &cfg),
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

// statusHandler is the interim API for part 2: enough to observe the pool
// booting. The full REST surface replaces it.
func statusHandler(fleet *tor.Fleet, cfg *config.Config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		if fleet.ReadyCount() == 0 {
			http.Error(w, "no ready instances", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /api/instances", func(w http.ResponseWriter, _ *http.Request) {
		type instanceView struct {
			ID          int    `json:"id"`
			Ready       bool   `json:"ready"`
			Running     bool   `json:"running"`
			Bootstrap   int    `json:"bootstrap"`
			Pid         int    `json:"pid"`
			UptimeSecs  int    `json:"uptime_secs"`
			SocksAddr   string `json:"socks_addr"`
			ExitIP      string `json:"exit_ip"`
			ExitCountry string `json:"exit_country"`
			ExitNick    string `json:"exit_nickname"`
		}

		instances := fleet.Instances()
		out := make([]instanceView, 0, len(instances))
		for _, inst := range instances {
			// Refresh opportunistically: the exit relay only becomes knowable
			// once a circuit is built, which is after bootstrap completes.
			if inst.Ready() && inst.ExitNode().Address == "" {
				_, _ = inst.RefreshExitNode()
			}
			node := inst.ExitNode()
			out = append(out, instanceView{
				ID:          inst.Index(),
				Ready:       inst.Ready(),
				Running:     inst.Running(),
				Bootstrap:   inst.Bootstrap(),
				Pid:         inst.Pid(),
				UptimeSecs:  int(time.Since(inst.StartedAt()).Seconds()),
				SocksAddr:   inst.Config().SocksAddr(),
				ExitIP:      node.Address,
				ExitCountry: node.Country,
				ExitNick:    node.Nickname,
			})
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("GET /api/pool", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"version":    version,
			"size":       fleet.Size(),
			"ready":      fleet.ReadyCount(),
			"pool_size":  cfg.PoolSize,
			"socks_port": cfg.SocksPort,
			"http_port":  cfg.HTTPPort,
		})
	})

	return mux
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
