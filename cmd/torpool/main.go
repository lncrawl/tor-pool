// Command torpool runs a pool of tor instances behind a single sticky proxy
// endpoint, with a REST API and dashboard for managing them.
//
// It is designed to be PID 1 in its container: it owns the tor child processes
// and must shut them down itself, since nothing else will reap them.
package main

import (
	"context"
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
	"github.com/lncrawl/tor-pool/internal/server"
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
		ConfluxEnabled:      cfg.ConfluxEnabled,
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

	api := &http.Server{
		Addr:              net.JoinHostPort(cfg.BindHost, strconv.Itoa(cfg.APIPort)),
		Handler:           server.New(p, &cfg, version, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: /api/stream is a long-lived SSE connection and any
		// deadline here would sever the dashboard on a fixed interval.
	}
	go func() {
		log.Info("api listening", "addr", api.Addr)
		if err := api.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("api server", "error", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := api.Shutdown(shutdownCtx); err != nil {
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

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)
	return log
}
