package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/pool"
	"github.com/lncrawl/tor-pool/internal/tor"
)

// newTestServer builds a server over an empty fleet.
//
// No tor process is started, so every instance-scoped route sees an empty pool
// — which is exactly the edge the handlers most often get wrong.
func newTestServer(t *testing.T) *Server {
	t.Helper()

	cfg := config.Defaults()
	log := slog.New(slog.DiscardHandler)
	fleet := tor.NewFleet(tor.FleetOptions{
		Size:           0,
		Binary:         "tor",
		DataDir:        t.TempDir(),
		SocksPortFor:   cfg.InstanceSocksPort,
		ControlPortFor: cfg.InstanceControlPort,
	}, log)

	return New(pool.New(&cfg, fleet, log), &cfg, "test", log)
}

func do(t *testing.T, s *Server, method, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestHealthIsUnhealthyWithNoRoutableInstances(t *testing.T) {
	s := newTestServer(t)
	if got := do(t, s, http.MethodGet, "/health", "").Code; got != http.StatusServiceUnavailable {
		t.Errorf("/health = %d, want 503 when nothing can serve", got)
	}
}

func TestPoolSummary(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/api/pool", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var view PoolView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Version != "test" {
		t.Errorf("Version = %q, want test", view.Version)
	}
	if view.Config.PoolSize != config.Defaults().PoolSize {
		t.Errorf("Config.PoolSize = %d, want the configured value", view.Config.PoolSize)
	}
}

func TestEmptyCollectionsSerialiseAsArrays(t *testing.T) {
	// A nil slice would marshal to null and break every consumer that iterates
	// the response without a guard.
	s := newTestServer(t)
	for _, path := range []string{"/api/instances", "/api/sessions", "/api/events", "/api/stats/history"} {
		body := strings.TrimSpace(do(t, s, http.MethodGet, path, "").Body.String())
		if !strings.HasPrefix(body, "[") {
			t.Errorf("%s returned %q, want a JSON array", path, body)
		}
	}
}

func TestUnknownInstanceIs404(t *testing.T) {
	s := newTestServer(t)
	for _, path := range []string{
		"/api/instances/99",
	} {
		if got := do(t, s, http.MethodGet, path, "").Code; got != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, got)
		}
	}
	for _, path := range []string{
		"/api/instances/99/rotate",
		"/api/instances/99/restart",
		"/api/instances/99/quarantine",
		"/api/instances/99/release",
	} {
		if got := do(t, s, http.MethodPost, path, "").Code; got != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", path, got)
		}
	}
}

func TestNonNumericInstanceIdIsRejected(t *testing.T) {
	s := newTestServer(t)
	if got := do(t, s, http.MethodPost, "/api/instances/abc/rotate", "").Code; got != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", got)
	}
}

func TestUnknownSessionIs404(t *testing.T) {
	s := newTestServer(t)
	if got := do(t, s, http.MethodGet, "/api/sessions/ghost", "").Code; got != http.StatusNotFound {
		t.Errorf("GET session = %d, want 404", got)
	}
	if got := do(t, s, http.MethodPost, "/api/sessions/ghost/failure", `{"reason":"x"}`).Code; got != http.StatusNotFound {
		t.Errorf("POST failure = %d, want 404", got)
	}
	if got := do(t, s, http.MethodDelete, "/api/sessions/ghost", "").Code; got != http.StatusNotFound {
		t.Errorf("DELETE session = %d, want 404", got)
	}
}

func TestRotateWithNoInstancesIsUnavailable(t *testing.T) {
	// Not a 500: there is nothing wrong with the server, it simply has no
	// instance to move the caller to.
	s := newTestServer(t)
	if got := do(t, s, http.MethodPost, "/api/sessions/any/rotate", "").Code; got != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", got)
	}
}

func TestResizeRejectsBadInput(t *testing.T) {
	s := newTestServer(t)
	if got := do(t, s, http.MethodPost, "/api/pool/resize", "not json").Code; got != http.StatusBadRequest {
		t.Errorf("malformed body = %d, want 400", got)
	}
	if got := do(t, s, http.MethodPost, "/api/pool/resize", `{"size":0}`).Code; got != http.StatusBadRequest {
		t.Errorf("zero size = %d, want 400", got)
	}
	// A size the port layout cannot hold is not a big pool: accepting it spawns
	// thousands of tor processes that cannot bind, and the pool never comes back.
	if got := do(t, s, http.MethodPost, "/api/pool/resize", `{"size":99999}`).Code; got != http.StatusBadRequest {
		t.Errorf("unrunnable size = %d, want 400", got)
	}
}

func TestMetricsExposition(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"# HELP torpool_instances_total",
		"# TYPE torpool_instances_total gauge",
		"torpool_sessions_active",
		"torpool_requests_total",
		`torpool_bytes_total{direction="up"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}

	// Every metric must be preceded by HELP and TYPE, or scrapers complain.
	for line := range strings.SplitSeq(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, " ") {
			t.Errorf("malformed metric line: %q", line)
		}
	}
}

func TestDrainAnswers404ForUnknownInstance(t *testing.T) {
	// Like every other per-instance action. Answering 200 with sessions_moved: 0
	// left a caller unable to tell "it had no sessions" from "it does not exist",
	// which is precisely the case the dashboard hits when a resize retires the
	// row underneath the button.
	s := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/api/instances/5/drain", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestEventsRespectsLimit(t *testing.T) {
	s := newTestServer(t)
	// Generate more events than the limit asks for.
	for range 5 {
		s.pool.Events().Instance("test", 1, "something happened", "")
	}

	rec := do(t, s, http.MethodGet, "/api/events?limit=2", "")
	var events []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("returned %d events, want 2", len(events))
	}
}

func TestRootServesTheDashboard(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/", "")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<title>tor-pool</title>") {
		t.Errorf("root did not serve the dashboard document, got: %.120s", rec.Body.String())
	}
	// index.html must never be cached, or a redeploy keeps serving the old
	// bundle from the browser's cache.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
}

func TestUnknownPathFallsBackToTheDashboard(t *testing.T) {
	// A bookmarked deep link is the dashboard's job, not a 404 — the router
	// resolves it client-side.
	s := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/instances", "")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<title>tor-pool</title>") {
		t.Error("a deep link should serve the dashboard document")
	}
}

func TestUnknownAPIPathIs404(t *testing.T) {
	// The SPA fallback must not swallow a mistyped API route and hand back
	// HTML with a 200.
	s := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/api/nope", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 — API paths must not fall through to the SPA", rec.Code)
	}
}
