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
	"strings"
	"syscall"
	"time"

	"github.com/lncrawl/tor-pool/internal/auth"
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

	// Credentials are resolved before anything expensive starts: a data
	// directory that cannot be written must fail now rather than after a
	// two-minute tor bootstrap.
	credentials, boot, err := auth.Open(&cfg, p.Events(), log)
	if err != nil {
		return fmt.Errorf("open credential store: %w", err)
	}
	reportBootstrap(&cfg, boot)
	// Last, so it is the final thing in the startup log rather than something
	// scrolled past.
	reportAuthDisabled(&cfg)

	// Registered after the fleet's shutdown so that it runs before it: defers are
	// LIFO, and a slow tor exit would otherwise eat the flush window.
	defer func() {
		if err := credentials.Flush(); err != nil {
			log.Error("flush token usage", "error", err)
		}
	}()
	go credentials.Run(ctx)

	go p.Run(ctx)

	proxies := proxy.NewServer(&cfg, p, credentials.CheckProxy, log)
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
		Handler:           server.New(p, credentials, &cfg, version, log).Handler(),
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

// reportBootstrap prints credentials generated during this boot, exactly once.
//
// Written straight to stderr rather than through slog, which is what main
// already does for a configuration error: a structured handler would fold this
// into one quoted attribute, and the whole value of the block is that an operator
// reading `docker logs` cannot miss it. This is the only moment the plaintext
// exists — the store keeps digests — so anything lost here is lost.
func reportBootstrap(cfg *config.Config, boot auth.Bootstrap) {
	if !boot.Any() {
		return
	}

	rule := strings.Repeat("=", 74)
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\n", rule)
	b.WriteString("  torpool generated credentials on this boot. Save them now: only\n")
	b.WriteString("  their digests are stored, and they will not be shown again.\n")

	if boot.AdminPassword != "" {
		fmt.Fprintf(&b, "\n  dashboard    %s / %s\n", boot.AdminUser, boot.AdminPassword)
		b.WriteString("               set ADMIN_PASSWORD to choose your own instead\n")
	}
	if boot.ProxyToken != "" {
		fmt.Fprintf(&b, "\n  proxy token  %s\n", boot.ProxyToken)
		if cfg.SocksPort != 0 {
			fmt.Fprintf(&b, "               socks5h://<session>:%s@host:%d\n",
				boot.ProxyToken, cfg.SocksPort)
		}
		b.WriteString("               set PROXY_TOKEN to choose your own instead\n")
	}

	if cfg.AuthDisabled {
		// They were still generated, so that clearing the flag is a restart and
		// not a fresh round of provisioning. Say plainly that they do nothing yet,
		// or this block reads as a pool that is asking for credentials it is not.
		b.WriteString("\n  AUTH_DISABLED is set, so nothing above is being checked yet.\n")
		b.WriteString("  These are what will work once you unset it and restart.\n")
	}

	fmt.Fprintf(&b, "\n  Stored in %s\n", cfg.DataDir)
	b.WriteString("  Mount that path as a volume, or they are regenerated whenever the\n")
	b.WriteString("  container is recreated.\n")
	fmt.Fprintf(&b, "%s\n\n", rule)

	_, _ = os.Stderr.WriteString(b.String())
}

// reportAuthDisabled says loudly that every credential check is off.
//
// A warning line through slog is not enough here. It scrolls past among the
// instance bootstrap chatter, and the whole risk of this flag is an operator who
// set it on a laptop months ago and no longer remembers it is set — by which time
// the only place it is written down is the environment. Same stderr block as the
// credential banner, for the same reason: it has to be impossible to miss in
// `docker logs`.
func reportAuthDisabled(cfg *config.Config) {
	if !cfg.AuthDisabled {
		return
	}

	rule := strings.Repeat("=", 74)
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\n", rule)
	b.WriteString("  AUTHENTICATION IS DISABLED (AUTH_DISABLED)\n\n")
	b.WriteString("  Every proxy connection and every API request is accepted with no\n")
	b.WriteString("  credential. Anyone who can reach these ports has your Tor bandwidth,\n")
	b.WriteString("  the session table, and the ability to restart instances.\n")
	fmt.Fprintf(&b, "\n  Reachable on %s:", cfg.BindHost)
	if cfg.SocksPort != 0 {
		fmt.Fprintf(&b, " socks %d", cfg.SocksPort)
	}
	if cfg.HTTPPort != 0 {
		fmt.Fprintf(&b, " · http %d", cfg.HTTPPort)
	}
	fmt.Fprintf(&b, " · api %d\n", cfg.APIPort)
	// Naming the publish rather than BIND_HOST on purpose: in a container the
	// bind is 0.0.0.0 by necessity, so it is the host-side mapping that decides
	// who can actually connect, and that is what an operator has to go and check.
	b.WriteString("  Only safe if the host publishes these to 127.0.0.1. Unset the\n")
	b.WriteString("  variable and restart to turn checking back on.\n")
	fmt.Fprintf(&b, "%s\n\n", rule)

	_, _ = os.Stderr.WriteString(b.String())
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
