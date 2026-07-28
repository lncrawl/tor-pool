package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/lncrawl/tor-pool/internal/auth"
)

// publicPaths is the complete set of endpoints that may answer without a
// credential, and the reason each one is on the list.
//
// Adding to it is a security decision, so it is spelled out here rather than
// inferred: TestEveryRouteIsGuarded fails for any route that is public without
// being named, which makes forgetting a scope a test failure rather than a
// silently open endpoint.
var publicPaths = map[string]string{
	"/health":         "probed by the container healthcheck and by CI",
	"/metrics":        "scraped on a trusted network",
	"/api/auth/login": "has to be reachable to be useful; rate limited instead",
}

// The reason the route table is data. Registered one HandleFunc at a time,
// authentication is default-open: the failure mode is an endpoint added months
// from now without a scope, which nothing catches. ServeMux does not expose its
// registered patterns, so this test could not exist without the table.
func TestEveryRouteIsGuarded(t *testing.T) {
	s := newTestServer(t)
	for _, rt := range s.routes() {
		if _, public := publicPaths[rt.path]; public {
			if rt.need != "" {
				t.Errorf("%s %s is in publicPaths but declares scope %q",
					rt.method, rt.path, rt.need)
			}
			continue
		}
		if rt.need == "" {
			t.Errorf("%s %s is public but is not in publicPaths — "+
				"give it a scope, or add it there with a reason",
				rt.method, rt.path)
		}
	}
}

// Every guarded route must actually refuse an anonymous caller. The table says
// what should happen; this drives real requests through the mux to prove it does.
func TestGuardedRoutesRefuseAnonymousCallers(t *testing.T) {
	s := newTestServer(t)
	for _, rt := range s.routes() {
		if rt.need == "" {
			continue
		}
		method := rt.method
		if method == "" {
			method = http.MethodGet
		}
		// Path parameters need a concrete value to route at all.
		path := strings.NewReplacer("{id}", "0", "{key}", "somekey").Replace(rt.path)

		rec := doAs(t, s, "", method, path, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a credential = %d, want 401", method, path, rec.Code)
		}
		// RFC 9110 §15.5.2 makes this a MUST, and clients rely on it to know
		// what kind of credential to send.
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s %s: 401 without a WWW-Authenticate header", method, path)
		}
	}
}

func TestPublicRoutesNeedNoCredential(t *testing.T) {
	s := newTestServer(t)

	// If /health ever regresses to needing a credential, the compose healthcheck
	// marks the container unhealthy forever and nothing else reports why.
	if rec := doAs(t, s, "", http.MethodGet, "/health", ""); rec.Code == http.StatusUnauthorized {
		t.Error("/health requires a credential; the container healthcheck cannot send one")
	}
	if rec := doAs(t, s, "", http.MethodGet, "/metrics", ""); rec.Code != http.StatusOK {
		t.Errorf("/metrics = %d, want 200 without a credential", rec.Code)
	}
	// The bundle must load unauthenticated or the browser has no way to render a
	// login screen in the first place.
	rec := doAs(t, s, "", http.MethodGet, "/", "")
	if rec.Code != http.StatusOK {
		t.Errorf("/ = %d, want 200 without a credential", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<title>tor-pool</title>") {
		t.Error("/ did not serve the dashboard document to an anonymous caller")
	}
}

// An unmatched API path must be authenticated before it 404s, so the surface does
// not report which endpoints exist.
func TestUnknownAPIPathIsAuthenticatedFirst(t *testing.T) {
	s := newTestServer(t)
	for _, method := range []string{
		http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPut,
	} {
		if rec := doAs(t, s, "", method, "/api/nope", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s /api/nope = %d, want 401 — an unmatched path must not reveal itself",
				method, rec.Code)
		}
	}
}

// The whole point of scoping: the credential a scraper holds must not be able to
// administer the pool.
func TestProxyTokenCannotAdminister(t *testing.T) {
	s := newTestServer(t)

	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/pool/resize", `{"size":2}`},
		{http.MethodPost, "/api/pool/rotate", ""},
		{http.MethodGet, "/api/instances", ""},
		{http.MethodGet, "/api/sessions", ""},
		{http.MethodGet, "/api/tokens", ""},
		{http.MethodPost, "/api/tokens", `{"name":"escalated","scope":"admin"}`},
		{http.MethodGet, "/api/events", ""},
	} {
		rec := doAs(t, s, s.token, c.method, c.path, c.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with a proxy token = %d, want 403", c.method, c.path, rec.Code)
		}
		// A 403 must not carry a challenge: the credential is valid and merely
		// insufficient, so a client that retries on one would loop, and the
		// dashboard would sign itself out over a permissions error.
		if h := rec.Header().Get("WWW-Authenticate"); h != "" {
			t.Errorf("%s %s: 403 carried WWW-Authenticate %q", c.method, c.path, h)
		}
	}
}

// The routes a scraper legitimately needs must accept its own token.
func TestProxyTokenReachesItsOwnSessionRoutes(t *testing.T) {
	s := newTestServer(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/sessions/unknown-key"},
		{http.MethodPost, "/api/sessions/unknown-key/rotate"},
		{http.MethodPost, "/api/sessions/unknown-key/failure"},
	} {
		rec := doAs(t, s, s.token, c.method, c.path, "")
		// 404 for a session that does not exist is the right answer; 401 or 403
		// would mean the scope mapping is wrong.
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("%s %s with a proxy token = %d, want the handler to run",
				c.method, c.path, rec.Code)
		}
	}
}

func TestLoginIssuesAWorkingCredential(t *testing.T) {
	s := newTestServer(t)

	rec := doAs(t, s, "", http.MethodPost, "/api/auth/login",
		`{"user":"admin","password":"`+testPassword+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Token == "" || got.Expires == 0 {
		t.Fatalf("response = %+v, want a token and an expiry", got)
	}
	if strings.Contains(rec.Body.String(), testPassword) {
		t.Error("the login response echoed the password back")
	}
	if code := doAs(t, s, got.Token, http.MethodGet, "/api/pool", "").Code; code != http.StatusOK {
		t.Errorf("the issued token was rejected by /api/pool: %d", code)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	s := newTestServer(t)
	for name, body := range map[string]string{
		"wrong password": `{"user":"admin","password":"nope"}`,
		"wrong user":     `{"user":"root","password":"` + testPassword + `"}`,
		"empty":          `{}`,
	} {
		rec := doAs(t, s, "", http.MethodPost, "/api/auth/login", body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, rec.Code)
		}
		// The body must not say which half was wrong.
		if b := strings.ToLower(rec.Body.String()); strings.Contains(b, "user") ||
			strings.Contains(b, "password") {
			t.Errorf("%s: response narrows the failure: %q", name, rec.Body.String())
		}
	}

	if rec := doAs(t, s, "", http.MethodPost, "/api/auth/login", "not json"); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body = %d, want 400", rec.Code)
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	s := newTestServer(t)
	// Defaults allow ten a minute; the eleventh must be refused even though this
	// one carries the right password.
	for range 10 {
		doAs(t, s, "", http.MethodPost, "/api/auth/login", `{"user":"admin","password":"nope"}`)
	}
	rec := doAs(t, s, "", http.MethodPost, "/api/auth/login",
		`{"user":"admin","password":"`+testPassword+`"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 without a Retry-After header")
	}
}

func TestStreamAcceptsATicketAndNothingElse(t *testing.T) {
	s := newTestServer(t)

	rec := doAs(t, s, s.jwt, http.MethodPost, "/api/auth/ticket", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ticket = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got ticketResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Ticket == "" || got.ExpiresIn <= 0 {
		t.Fatalf("response = %+v, want a ticket and a lifetime", got)
	}

	// A ticket in the query string is the only way EventSource can authenticate.
	//
	// The context is cancelled up front because the handler is an endless stream:
	// it writes its first frame and then returns on a done context, which is
	// enough to prove the guard let it through.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := newRequest(http.MethodGet, "/api/stream?ticket="+got.Ticket, "").WithContext(ctx)
	if code := serve(s, req).Code; code != http.StatusOK {
		t.Errorf("a valid ticket was refused by the stream: %d", code)
	}
	for name, query := range map[string]string{
		"no ticket":      "",
		"empty ticket":   "?ticket=",
		"garbage ticket": "?ticket=nonsense",
		// A JWT is not a ticket. Accepting one here would not be a hole, but
		// accepting a *ticket* on the API would be, and the asymmetry is only
		// coherent if each audience is checked where it belongs.
		"api jwt as ticket": "?ticket=" + s.jwt,
	} {
		if code := doAs(t, s, "", http.MethodGet, "/api/stream"+query, "").Code; code != http.StatusUnauthorized {
			t.Errorf("stream with %s = %d, want 401", name, code)
		}
	}

	// And a ticket must not open the rest of the API, or a credential that
	// travels in URLs by construction becomes an operator session.
	if code := doAs(t, s, got.Ticket, http.MethodGet, "/api/pool", "").Code; code != http.StatusUnauthorized {
		t.Errorf("a stream ticket reached /api/pool: %d", code)
	}
	// Nor mint another, or its short life is decorative.
	if code := doAs(t, s, got.Ticket, http.MethodPost, "/api/auth/ticket", "").Code; code != http.StatusUnauthorized {
		t.Errorf("a stream ticket minted another ticket: %d", code)
	}
}

func TestTokenLifecycle(t *testing.T) {
	s := newTestServer(t)

	rec := do(t, s, http.MethodPost, "/api/tokens", `{"name":"scraper","scope":"proxy"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint = %d: %s", rec.Code, rec.Body.String())
	}
	var minted mintResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if minted.Secret == "" || minted.ID == "" {
		t.Fatalf("response = %+v, want a secret and an id", minted)
	}
	if minted.Scope != auth.ScopeProxy {
		t.Errorf("Scope = %q, want proxy", minted.Scope)
	}

	// Listing must never repeat the secret: it exists in exactly one response.
	list := do(t, s, http.MethodGet, "/api/tokens", "")
	if strings.Contains(list.Body.String(), minted.Secret) {
		t.Error("the token list contains a secret")
	}
	var infos []auth.TokenInfo
	if err := json.Unmarshal(list.Body.Bytes(), &infos); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	var found bool
	for _, info := range infos {
		if info.ID == minted.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("token %s is missing from the list", minted.ID)
	}

	if code := do(t, s, http.MethodDelete, "/api/tokens/"+minted.ID, "").Code; code != http.StatusNoContent {
		t.Errorf("revoke = %d, want 204", code)
	}
	if code := do(t, s, http.MethodDelete, "/api/tokens/"+minted.ID, "").Code; code != http.StatusNotFound {
		t.Errorf("revoking twice = %d, want 404", code)
	}
}

func TestMintRejectsBadInput(t *testing.T) {
	s := newTestServer(t)
	for name, body := range map[string]string{
		"no name":       `{"scope":"proxy"}`,
		"unknown scope": `{"name":"x","scope":"root"}`,
		"no scope":      `{"name":"x"}`,
		"not json":      `nope`,
	} {
		if code := do(t, s, http.MethodPost, "/api/tokens", body).Code; code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, code)
		}
	}
}

// PoolConfig is a hand-written allowlist today, which is what keeps the password
// out of it. This fails the moment someone replaces it with the whole Config.
func TestPoolViewNeverLeaksCredentials(t *testing.T) {
	s := newTestServer(t)
	body := do(t, s, http.MethodGet, "/api/pool", "").Body.String()
	if strings.Contains(body, testPassword) {
		t.Error("/api/pool exposes the admin password")
	}
	if strings.Contains(strings.ToLower(body), "password") {
		t.Errorf("/api/pool mentions a password: %s", body)
	}
}

// The scheme is case-insensitive per RFC 9110 §11.1, and curl users type it in
// whatever case they like.
func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	s := newTestServer(t)
	for _, header := range []string{"Bearer " + s.jwt, "bearer " + s.jwt, "BEARER " + s.jwt} {
		req := newRequest(http.MethodGet, "/api/pool", "")
		req.Header.Set("Authorization", header)
		rec := serve(s, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Authorization %q = %d, want 200", header, rec.Code)
		}
	}
	for _, header := range []string{s.jwt, "Basic " + s.jwt, "Bearer", ""} {
		req := newRequest(http.MethodGet, "/api/pool", "")
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		if rec := serve(s, req); rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q = %d, want 401", header, rec.Code)
		}
	}
}
