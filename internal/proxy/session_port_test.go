package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/lncrawl/tor-pool/internal/config"
)

// openSocksHandshake performs the client half of a credential-free SOCKS5
// negotiation and a CONNECT, in the background.
//
// username is sent when non-empty, which is how a test proves a session port
// ignores it rather than merely never seeing one. With authentication off the
// server still selects user/pass when it is offered, because that is where the
// key would be, so the sub-negotiation has to be completed either way.
//
// Every read lives in this one goroutine and the CONNECT reply comes back on the
// channel. net.Pipe is synchronous, so a second reader in the test would race
// this one for the server's bytes.
func openSocksHandshake(client io.ReadWriter, username string) <-chan []byte {
	out := make(chan []byte, 1)
	go func() {
		if username == "" {
			_, _ = client.Write([]byte{socks5Version, 1, authNone})
			drain(client, 2)
		} else {
			_, _ = client.Write([]byte{socks5Version, 2, authNone, authUserPass})
			drain(client, 2)
			_, _ = client.Write([]byte{userPassVersion, byte(len(username))})
			_, _ = client.Write([]byte(username))
			_, _ = client.Write([]byte{byte(len(testToken))})
			_, _ = client.Write([]byte(testToken))
			drain(client, 2)
		}
		host := "example.com"
		req := []byte{socks5Version, cmdConnect, 0x00, atypDomain, byte(len(host))}
		req = append(req, host...)
		req = append(req, 0x01, 0xbb)
		_, _ = client.Write(req)

		buf := make([]byte, 10)
		_, _ = io.ReadFull(client, buf)
		out <- buf
	}()
	return out
}

func newSessionPortServer(t *testing.T, router Router) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.AuthDisabled = true
	cfg.SessionPortBase = 19600
	return NewServer(&cfg, router, acceptToken, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// The behaviour the whole feature exists for: which instance serves is decided
// by the port, and the session router is never consulted.
func TestSessionPortUsesItsOwnInstanceAndNotTheRouter(t *testing.T) {
	router := &fakeRouter{addr: fakeTor(t)}
	s := newSessionPortServer(t, router)

	client, server := newClientServer(t)
	openSocksHandshake(client, "")
	s.handlePinnedSocks(context.Background(), server, 3)

	if got := router.pinned(); len(got) != 1 || got[0] != 3 {
		t.Errorf("addressed instances = %v, want [3]", got)
	}
	if routes, _, _ := router.counts(); routes != 0 {
		t.Errorf("RouteAddr called %d times, want 0 — the port decides, not the session", routes)
	}
}

// A username is legal on this port and must not steer anything: it names a
// session, and the session is precisely what this port is not routing by.
func TestSessionPortIgnoresASuppliedSessionKey(t *testing.T) {
	router := &fakeRouter{addr: fakeTor(t)}
	s := newSessionPortServer(t, router)

	client, server := newClientServer(t)
	openSocksHandshake(client, "somebody-elses-session")
	s.handlePinnedSocks(context.Background(), server, 2)

	if got := router.pinned(); len(got) != 1 || got[0] != 2 {
		t.Errorf("addressed instances = %v, want [2]", got)
	}
	if routes, _, _ := router.counts(); routes != 0 {
		t.Errorf("RouteAddr called %d times, want 0", routes)
	}
}

// An unusable instance has to fail rather than divert. Diverting would hand back
// a different exit relay, which is the exact failure the port exists to prevent.
func TestSessionPortFailsRatherThanSubstitutingAnInstance(t *testing.T) {
	router := &fakeRouter{addr: fakeTor(t), instanceErr: errors.New("not ready")}
	s := newSessionPortServer(t, router)

	client, server := newClientServer(t)
	reply := openSocksHandshake(client, "")
	s.handlePinnedSocks(context.Background(), server, 1)

	got := <-reply
	if len(got) < 2 || got[1] != replyGeneralFailure {
		t.Errorf("reply = %v, want a general failure in byte 1", got)
	}
	if routes, _, _ := router.counts(); routes != 0 {
		t.Errorf("RouteAddr called %d times, want 0 — no fallback to another instance", routes)
	}
}

// The listeners take no credentials, so binding them beside listeners that do
// would quietly undo the password. Refused at boot instead.
func TestSessionPortsRefuseToStartWithAuthEnabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.SessionPortBase = 19600
	cfg.AuthDisabled = false
	s := NewServer(&cfg, &fakeRouter{}, acceptToken, slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := s.startSessionPorts(context.Background())
	if err == nil {
		t.Fatal("startSessionPorts succeeded with authentication on, want an error")
	}
	t.Cleanup(func() { _ = s.Close() })
}

// Unset stays unset: no listener, and no complaint about authentication either.
func TestSessionPortsAreOffByDefault(t *testing.T) {
	cfg := config.Defaults()
	if cfg.SessionPortBase != 0 {
		t.Fatalf("SessionPortBase defaults to %d, want 0", cfg.SessionPortBase)
	}
	s := NewServer(&cfg, &fakeRouter{}, acceptToken, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.startSessionPorts(context.Background()); err != nil {
		t.Fatalf("startSessionPorts with the feature off: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
}
