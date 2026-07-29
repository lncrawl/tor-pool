package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/pool"
)

// Outcome re-exports the pool's connection outcome so callers of this package
// need only one import.
type Outcome = pool.Outcome

// Router is the pool behaviour the listeners depend on. Keeping it an interface
// means the proxy layer can be tested without a live fleet.
type Router interface {
	// Route returns the SOCKS address of the instance this session should use.
	RouteAddr(sessionKey string) (instance int, socksAddr string, err error)
	// Finish records the outcome of a completed connection.
	Finish(sessionKey string, out Outcome)
	// RecordTransportFailure attributes a transport-level failure to an
	// instance, independent of any session.
	RecordTransportFailure(instance int, reason string)
	// SampleExit asks the pool to re-read an instance's exit relay while one of
	// its connections is live.
	SampleExit(instance int)
}

// credentialCheck verifies a proxy password.
//
// A function type rather than an interface because that is the whole dependency,
// and declaring it here rather than importing internal/auth keeps the handshake
// tests free of a credential store — the same reason Router is declared here.
//
// A nil check means authentication is disabled and the listeners must not
// challenge at all. That is a distinct state from a check that accepts
// everything: SOCKS5 refuses a client offering only "no authentication", and the
// HTTP proxy answers 407 to a request with no Proxy-Authorization header, both
// before any password exists to be accepted. Nil arrives from exactly one place,
// Server.credentials, so there is a single line to read to know when it happens.
type credentialCheck func(secret string) error

// handshakeTimeout bounds how long a client may take to complete a SOCKS5
// handshake.
//
// Without one, a client that connects and sends a single byte holds a goroutine
// and a file descriptor indefinitely. That was always true; mandatory
// authentication makes stalling mid-handshake the cheapest way to attack the
// port, so it is no longer only a tidiness question.
const handshakeTimeout = 30 * time.Second

// exitSampleDelay is how long after a connection is established the instance's
// exit relay is sampled.
//
// The exit is resolved by asking tor which circuit currently carries a stream,
// and that only works while a stream exists. Sampling between requests finds no
// stream and falls back to guessing from the newest built circuit — which is
// often one tor built preemptively and no traffic ever used. A short delay lands
// the query inside the connection's lifetime.
const exitSampleDelay = 250 * time.Millisecond

// Server owns the client-facing listeners.
type Server struct {
	cfg    *config.Config
	router Router
	verify credentialCheck
	log    *slog.Logger

	mu        sync.Mutex
	listeners []net.Listener
}

// NewServer builds the proxy listeners. Nothing binds until Start.
func NewServer(cfg *config.Config, router Router, verify credentialCheck, log *slog.Logger) *Server {
	return &Server{cfg: cfg, router: router, verify: verify, log: log}
}

// credentials is the check the handshake must apply, or nil when AUTH_DISABLED
// has switched authentication off.
//
// The flag is consulted here rather than at each use so that the whole listener
// side of the decision is one function. The verifier is kept, not discarded: a
// caller that still sends a token is still sending a session key alongside it,
// and that key is the reason the credential travels in a proxy URL at all.
func (s *Server) credentials() credentialCheck {
	if s.cfg.AuthDisabled {
		return nil
	}
	return s.verify
}

// Start binds the configured listeners and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if s.cfg.SocksPort != 0 {
		addr := net.JoinHostPort(s.cfg.BindHost, fmt.Sprint(s.cfg.SocksPort))
		if err := s.serve(ctx, "socks5", addr, s.handleSocks); err != nil {
			return err
		}
	}
	if s.cfg.HTTPPort != 0 {
		addr := net.JoinHostPort(s.cfg.BindHost, fmt.Sprint(s.cfg.HTTPPort))
		if err := s.serve(ctx, "http", addr, s.handleHTTP); err != nil {
			return err
		}
	}
	return nil
}

// serve binds one listener and accepts in the background.
func (s *Server) serve(ctx context.Context, name, addr string, handle func(context.Context, net.Conn)) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s on %s: %w", name, addr, err)
	}

	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()

	s.log.Info("proxy listening", "protocol", name, "addr", addr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				s.log.Warn("accept failed", "protocol", name, "error", err)
				continue
			}
			go handle(ctx, conn)
		}
	}()
	return nil
}

// Close stops every listener. In-flight connections finish on their own.
func (s *Server) Close() error {
	s.mu.Lock()
	listeners := s.listeners
	s.listeners = nil
	s.mu.Unlock()

	var errs []error
	for _, ln := range listeners {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// handleSocks serves one SOCKS5 client connection.
func (s *Server) handleSocks(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	if err := client.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}
	req, err := readSocksRequest(client, s.credentials())
	if err != nil {
		// A malformed handshake or a refused credential is the client's fault; no
		// instance is involved yet, so nothing is scored.
		//
		// Logged to stderr and deliberately not to the event log: that ring is
		// bounded, so one entry per refused connection would let anyone flush the
		// audit history in seconds, exactly when it matters.
		s.log.Warn("socks handshake failed", "remote", remoteHost(client), "error", err)
		return
	}
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	key := s.sessionKey(req.sessionKey, client)
	instance, socksAddr, err := s.router.RouteAddr(key)
	if err != nil {
		s.log.Warn("no instance for session", "session", key, "error", err)
		writeSocksReply(client, replyGeneralFailure)
		return
	}

	dialStart := time.Now()
	upstream, err := dialThroughInstance(ctx, socksAddr, req.target)
	if err != nil {
		s.reportDialFailure(instance, key, req.target, err)
		writeSocksReply(client, dialFailureReply(err))
		return
	}
	latency := time.Since(dialStart)
	defer func() { _ = upstream.Close() }()

	writeSocksReply(client, replySuccess)
	s.sampleExitSoon(ctx, instance)
	s.finish(key, instance, req.target, latency, relay(client, upstream))
}

// sampleExitSoon schedules an exit-relay sample inside this connection's
// lifetime. The pool debounces, so a burst of connections costs one query.
func (s *Server) sampleExitSoon(ctx context.Context, instance int) {
	go func() {
		timer := time.NewTimer(exitSampleDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			s.router.SampleExit(instance)
		}
	}()
}

// sessionKey resolves the key a connection is pinned by.
//
// A caller that supplied SOCKS credentials has named its own session. One that
// did not falls back to DEFAULT_SESSION, so plain curl still gets stickiness
// instead of hopping instances on every request.
func (s *Server) sessionKey(supplied string, conn net.Conn) string {
	if supplied != "" {
		return truncateKey(supplied)
	}
	switch s.cfg.DefaultSession {
	case config.SessionShared:
		return "shared"
	case config.SessionRandom:
		return "random-" + randomSuffix()
	case config.SessionFromIP:
		return "ip-" + remoteHost(conn)
	default:
		return "ip-" + remoteHost(conn)
	}
}

// truncateKey bounds a caller-supplied key. The SOCKS5 wire format already caps
// a username at 255 bytes, but the HTTP path has no such limit.
func truncateKey(key string) string {
	if len(key) > maxSessionKeyLen {
		return key[:maxSessionKeyLen]
	}
	return key
}

func randomSuffix() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A duplicate suffix only means two callers share a session, which is
		// already a supported state.
		return "fallback"
	}
	return hex.EncodeToString(b[:])
}

func remoteHost(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// reportDialFailure scores a failed upstream dial against its instance.
//
// Except when the destination was never reachable through tor to begin with. A
// loopback or private literal is refused by tor itself, so blaming the instance
// for it lets any caller quarantine the entire pool by asking for 127.0.0.1 a few
// times — measured at three requests with the default thresholds. The request is
// still recorded as failed, so the accounting stays honest; only the remediation
// ladder is spared.
func (s *Server) reportDialFailure(instance int, key string, t target, err error) {
	s.log.Info("upstream dial failed",
		"session", key, "instance", instance, "target", t.String(), "error", err)

	if unroutableTarget(t) {
		s.log.Warn("destination is unroutable through tor, not scored against the instance",
			"session", key, "instance", instance, "target", t.String())
	} else {
		var upstreamErr *UpstreamError
		reason := "dial_error"
		if errors.As(err, &upstreamErr) {
			reason = "socks_" + strings.ReplaceAll(socksReplyText(upstreamErr.Code), " ", "_")
		}
		s.router.RecordTransportFailure(instance, reason)
	}
	s.router.Finish(key, Outcome{Instance: instance, Failed: true})
}

// unroutableTarget reports whether tor could never have reached a destination
// whatever the instance's state.
//
// Only address literals. Whether a *hostname* resolves to something private is
// tor's business and unknowable here, and a name that fails to resolve genuinely
// can mean a broken circuit — so those stay the instance's problem.
func unroutableTarget(t target) bool {
	ip, err := netip.ParseAddr(t.host)
	if err != nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

// dialFailureReply maps an upstream failure onto the SOCKS reply code the client
// should see, so a client can distinguish "that host is unreachable" from "this
// proxy is broken".
func dialFailureReply(err error) byte {
	var upstreamErr *UpstreamError
	if errors.As(err, &upstreamErr) {
		return upstreamErr.Code
	}
	return replyHostUnreachable
}

// finish records a completed connection.
func (s *Server) finish(key string, instance int, t target, latency time.Duration, res relayResult) {
	failed := res.Err != nil
	if failed {
		s.log.Debug("relay ended with error",
			"session", key, "instance", instance, "target", t.String(), "error", res.Err)
		s.router.RecordTransportFailure(instance, "relay_error")
	}
	s.router.Finish(key, Outcome{
		Instance:  instance,
		BytesUp:   res.BytesUp,
		BytesDown: res.BytesDown,
		Latency:   latency,
		Failed:    failed,
	})
}
