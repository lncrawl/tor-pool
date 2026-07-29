package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/stats"
)

func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	return cfg
}

func open(t *testing.T, cfg *config.Config) (*Auth, Bootstrap) {
	t.Helper()
	a, boot, err := Open(cfg, stats.NewEventLog(64), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return a, boot
}

func TestFirstBootGeneratesUsableCredentials(t *testing.T) {
	cfg := testConfig(t)
	a, boot := open(t, &cfg)

	if !boot.Any() {
		t.Fatal("first boot generated nothing")
	}
	if boot.AdminPassword == "" {
		t.Error("no admin password was generated")
	}
	if boot.AdminUser != cfg.AdminUser {
		t.Errorf("AdminUser = %q, want %q", boot.AdminUser, cfg.AdminUser)
	}
	// A bootstrap token means the proxy works without opening the dashboard,
	// which is the whole point of generating one.
	if boot.ProxyToken == "" {
		t.Fatal("no bootstrap proxy token was generated")
	}

	if _, _, err := a.Login(cfg.AdminUser, boot.AdminPassword, "10.0.0.1"); err != nil {
		t.Errorf("login with the generated password failed: %v", err)
	}
	id, err := a.VerifyProxy(boot.ProxyToken)
	if err != nil {
		t.Fatalf("the generated proxy token was rejected: %v", err)
	}
	if id.Scope != ScopeProxy {
		t.Errorf("Scope = %q, want %q — a logged bootstrap credential must not be admin",
			id.Scope, ScopeProxy)
	}
}

func TestGeneratedCredentialsSurviveARestart(t *testing.T) {
	cfg := testConfig(t)
	_, boot := open(t, &cfg)

	// A restart that minted a new password would lock out anyone who had
	// bookmarked the dashboard, which is why the digest is persisted.
	again, next := open(t, &cfg)
	if next.AdminPassword != "" {
		t.Error("a second boot generated another admin password")
	}
	if next.ProxyToken != "" {
		t.Error("a second boot generated another bootstrap token")
	}
	if _, _, err := again.Login(cfg.AdminUser, boot.AdminPassword, "10.0.0.1"); err != nil {
		t.Errorf("the first boot's password stopped working: %v", err)
	}
	if _, err := again.VerifyProxy(boot.ProxyToken); err != nil {
		t.Errorf("the first boot's token stopped working: %v", err)
	}
}

// An operator-chosen password must leave no trace on disk: a digest of a human
// password is a dictionary target, and the pv claim already makes a change
// invalidate outstanding JWTs without one.
func TestConfiguredPasswordIsNeverWrittenToDisk(t *testing.T) {
	cfg := testConfig(t)
	cfg.AdminPassword = "correct horse battery staple"
	a, boot := open(t, &cfg)

	if boot.AdminPassword != "" {
		t.Error("a configured password was reported as generated")
	}

	raw, err := os.ReadFile(filepath.Join(cfg.DataDir, storeFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), cfg.AdminPassword) {
		t.Fatal("the store contains the configured password verbatim")
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.AdminDigest != "" {
		t.Error("a digest of the configured password reached the store")
	}

	if _, _, err := a.Login(cfg.AdminUser, cfg.AdminPassword, "10.0.0.1"); err != nil {
		t.Errorf("login with the configured password failed: %v", err)
	}
}

// Removing ADMIN_PASSWORD must mint a fresh one rather than silently fall back to
// whatever was generated before it was set.
func TestRemovingTheConfiguredPasswordMintsANewOne(t *testing.T) {
	cfg := testConfig(t)
	_, first := open(t, &cfg)
	if first.AdminPassword == "" {
		t.Fatal("expected a generated password on first boot")
	}

	withEnv := cfg
	withEnv.AdminPassword = "chosen-by-hand"
	open(t, &withEnv)

	// Back to no configured password: the old generated one must be gone.
	a, third := open(t, &cfg)
	if third.AdminPassword == "" {
		t.Fatal("expected a freshly generated password")
	}
	if third.AdminPassword == first.AdminPassword {
		t.Error("the previously generated password came back")
	}
	if _, _, err := a.Login(cfg.AdminUser, "chosen-by-hand", "10.0.0.1"); err == nil {
		t.Error("the removed configured password still works")
	}
}

// Changing the password must invalidate outstanding sessions immediately. Without
// this a compromise leaves every issued JWT alive until it expires.
func TestChangingThePasswordInvalidatesIssuedJWTs(t *testing.T) {
	cfg := testConfig(t)
	cfg.AdminPassword = "first-password"
	a, _ := open(t, &cfg)

	jwt, _, err := a.Login(cfg.AdminUser, cfg.AdminPassword, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyAPI(jwt); err != nil {
		t.Fatalf("a fresh JWT was rejected: %v", err)
	}

	changed := cfg
	changed.AdminPassword = "second-password"
	restarted, _ := open(t, &changed)
	if _, err := restarted.VerifyAPI(jwt); err == nil {
		t.Error("a JWT issued under the old password is still accepted")
	}
}

// Changing the username must invalidate them too, via the sub claim.
func TestChangingTheUsernameInvalidatesIssuedJWTs(t *testing.T) {
	cfg := testConfig(t)
	cfg.AdminPassword = "steady"
	a, _ := open(t, &cfg)

	jwt, _, err := a.Login(cfg.AdminUser, cfg.AdminPassword, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	renamed := cfg
	renamed.AdminUser = "someone-else"
	restarted, _ := open(t, &renamed)
	if _, err := restarted.VerifyAPI(jwt); err == nil {
		t.Error("a JWT issued for the old username is still accepted")
	}
}

func TestLoginRejectsBadCredentialsIdentically(t *testing.T) {
	cfg := testConfig(t)
	cfg.AdminPassword = "hunter2"
	a, _ := open(t, &cfg)

	cases := map[string][2]string{
		"wrong password": {cfg.AdminUser, "hunter3"},
		"wrong user":     {"nobody", "hunter2"},
		"both wrong":     {"nobody", "hunter3"},
		"empty":          {"", ""},
		// A prefix of the real password must not pass. ConstantTimeCompare over
		// digests rather than raw strings is what makes length irrelevant.
		"password prefix": {cfg.AdminUser, "hunter"},
		"password plus":   {cfg.AdminUser, "hunter22"},
	}
	for name, c := range cases {
		_, _, err := a.Login(c[0], c[1], "10.0.0."+name)
		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%s: error = %v, want ErrUnauthorized", name, err)
		}
	}
}

func TestLoginRateLimitIsPerAddressAndClearsOnSuccess(t *testing.T) {
	cfg := testConfig(t)
	cfg.AdminPassword = "hunter2"
	cfg.LoginRateLimit = 2
	a, _ := open(t, &cfg)

	for range cfg.LoginRateLimit {
		if _, _, err := a.Login(cfg.AdminUser, "wrong", "10.0.0.1"); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("error = %v, want ErrUnauthorized", err)
		}
	}
	// Over the limit the right password is refused too, or the limiter is a
	// speed bump rather than a limit.
	if _, _, err := a.Login(cfg.AdminUser, cfg.AdminPassword, "10.0.0.1"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("error = %v, want ErrRateLimited", err)
	}
	// Another address is unaffected.
	if _, _, err := a.Login(cfg.AdminUser, cfg.AdminPassword, "10.0.0.2"); err != nil {
		t.Errorf("a different address was rate limited: %v", err)
	}
	// And a success clears the counter, so earlier typos are not held against
	// the operator for the rest of the window.
	if _, _, err := a.Login(cfg.AdminUser, "wrong", "10.0.0.3"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
	if _, _, err := a.Login(cfg.AdminUser, cfg.AdminPassword, "10.0.0.3"); err != nil {
		t.Fatal(err)
	}
	for range cfg.LoginRateLimit {
		if _, _, err := a.Login(cfg.AdminUser, "wrong", "10.0.0.3"); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("the counter was not cleared by a success: %v", err)
		}
	}
}

func TestMintedTokenWorksAndRevokeIsImmediate(t *testing.T) {
	cfg := testConfig(t)
	a, _ := open(t, &cfg)

	secret, info, err := a.Mint("scraper", ScopeProxy)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(secret, tokenPrefix) {
		t.Errorf("secret = %q, want the %q prefix", secret, tokenPrefix)
	}
	// 25 characters: the prefix plus 22 of base62, which is just over 128 bits.
	if len(secret) != len(tokenPrefix)+tokenChars {
		t.Errorf("len(secret) = %d, want %d", len(secret), len(tokenPrefix)+tokenChars)
	}
	if info.ID == "" || info.Name != "scraper" || info.Scope != ScopeProxy {
		t.Errorf("info = %+v, want an id, the name and the proxy scope", info)
	}

	if _, err := a.VerifyProxy(secret); err != nil {
		t.Fatalf("a freshly minted token was rejected: %v", err)
	}
	if err := a.Revoke(info.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := a.VerifyProxy(secret); !errors.Is(err, ErrUnauthorized) {
		t.Error("a revoked token still works")
	}
}

func TestRevokedTokenStaysDeadAcrossARestart(t *testing.T) {
	cfg := testConfig(t)
	a, _ := open(t, &cfg)

	secret, info, err := a.Mint("temporary", ScopeProxy)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Revoke(info.ID); err != nil {
		t.Fatal(err)
	}

	// The failure this guards against: revoke answers 200, the container
	// restarts, and the token works again.
	restarted, _ := open(t, &cfg)
	if _, err := restarted.VerifyProxy(secret); err == nil {
		t.Error("a revoked token came back after a restart")
	}
}

func TestRevokeReportsAnUnknownToken(t *testing.T) {
	cfg := testConfig(t)
	a, _ := open(t, &cfg)
	if err := a.Revoke("nope"); !errors.Is(err, ErrNoSuchToken) {
		t.Errorf("error = %v, want ErrNoSuchToken", err)
	}
}

func TestMintValidatesItsInput(t *testing.T) {
	cfg := testConfig(t)
	a, _ := open(t, &cfg)

	cases := map[string]struct {
		name  string
		scope Scope
	}{
		"empty name":      {"", ScopeProxy},
		"whitespace name": {"   ", ScopeProxy},
		"long name":       {strings.Repeat("x", maxTokenNameLen+1), ScopeProxy},
		"unknown scope":   {"fine", Scope("root")},
		"empty scope":     {"fine", Scope("")},
	}
	for label, c := range cases {
		if _, _, err := a.Mint(c.name, c.scope); err == nil {
			t.Errorf("%s was accepted", label)
		}
	}
}

// PROXY_TOKEN is configuration: it works, it is visible, and it is not something
// the dashboard can delete out from under the environment that set it.
func TestEnvTokenWorksAndIsNotPersisted(t *testing.T) {
	cfg := testConfig(t)
	cfg.ProxyToken = tokenPrefix + "AAAABBBBCCCCDDDDEEEEFF"
	a, _ := open(t, &cfg)

	id, err := a.VerifyProxy(cfg.ProxyToken)
	if err != nil {
		t.Fatalf("PROXY_TOKEN was rejected: %v", err)
	}
	if id.Scope != ScopeProxy {
		t.Errorf("Scope = %q, want %q", id.Scope, ScopeProxy)
	}

	raw, err := os.ReadFile(filepath.Join(cfg.DataDir, storeFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), cfg.ProxyToken) {
		t.Error("PROXY_TOKEN was written to the store verbatim")
	}

	var found bool
	for _, info := range a.List() {
		if info.Source == "environment" {
			found = true
		}
	}
	if !found {
		t.Error("PROXY_TOKEN is not reported in the token list")
	}
	if err := a.Revoke("env"); !errors.Is(err, ErrEnvToken) {
		t.Errorf("error = %v, want ErrEnvToken", err)
	}

	// A configured token replaces the bootstrap one, so nothing is generated.
	restarted, boot := open(t, &cfg)
	if boot.ProxyToken != "" {
		t.Error("a bootstrap token was generated alongside PROXY_TOKEN")
	}
	if _, err := restarted.VerifyProxy(cfg.ProxyToken); err != nil {
		t.Errorf("PROXY_TOKEN stopped working after a restart: %v", err)
	}
}

// A generated credential must be alphanumeric all the way through. base64url's
// '-' and '_' are what let a token get word-broken by a terminal or half-selected
// by a double-click and come back subtly wrong, which then presents as a refused
// credential rather than as a mangled string.
func TestGeneratedCredentialsAreAlphanumeric(t *testing.T) {
	alnum := func(s string) bool {
		for _, r := range s {
			switch {
			case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
			default:
				return false
			}
		}
		return true
	}

	// Enough draws that a stray character from either alphabet shows up: base64url
	// emits one roughly every 12 characters, so 200 tokens would be certain to.
	for range 200 {
		secret, err := newSecret()
		if err != nil {
			t.Fatal(err)
		}
		body := strings.TrimPrefix(secret, tokenPrefix)
		if len(body) != tokenChars {
			t.Fatalf("secret body = %q, want %d characters", body, tokenChars)
		}
		if !alnum(body) {
			t.Fatalf("secret %q is not alphanumeric", secret)
		}

		// The id travels in a URL path and gets copied out of the dashboard, so it
		// is held to the same rule.
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != idChars || !alnum(id) {
			t.Fatalf("id = %q, want %d alphanumeric characters", id, idChars)
		}
	}
}

// Rejection sampling has to actually reject: folding a whole byte with `% 62`
// would make the first eight characters of the alphabet ~1.6% likelier, and the
// giveaway is that '0'..'7' then outnumber the rest. Checked as a distribution
// because there is no other way to see a bias from outside the function.
func TestRandomBase62IsUnbiased(t *testing.T) {
	const draws = 60000

	s, err := randomBase62(draws)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[rune]int, len(base62Alphabet))
	for _, r := range s {
		counts[r]++
	}
	if len(counts) != len(base62Alphabet) {
		t.Fatalf("saw %d distinct characters, want all %d", len(counts), len(base62Alphabet))
	}

	// The biased implementation over-represents the first eight by ~1.6%; this
	// bound is wide enough that a fair draw will not trip it and narrow enough
	// that the fold would. Expected count per character is draws/62 ≈ 967.
	expected := float64(draws) / float64(len(base62Alphabet))
	var favoured, rest float64
	for r, n := range counts {
		if strings.IndexRune(base62Alphabet, r) < 256%len(base62Alphabet) {
			favoured += float64(n)
		} else {
			rest += float64(n)
		}
		if float64(n) < expected*0.8 || float64(n) > expected*1.2 {
			t.Errorf("character %q appeared %d times, want about %.0f", r, n, expected)
		}
	}
	// Per-character over the eight favoured versus the other 54.
	favoured /= float64(256 % len(base62Alphabet))
	rest /= float64(len(base62Alphabet) - 256%len(base62Alphabet))
	if ratio := favoured / rest; ratio > 1.01 {
		t.Errorf("the first bytes of the alphabet are %.1f%% likelier — the sampling folds instead of rejecting",
			(ratio-1)*100)
	}
}

// The prefix is how API dispatch tells a token from a JWT, so one without it
// would silently never match.
func TestEnvTokenMustCarryThePrefix(t *testing.T) {
	cfg := testConfig(t)
	cfg.ProxyToken = "hunter2"
	_, _, err := Open(&cfg, nil, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("expected an error for a PROXY_TOKEN without the prefix")
	}
	if !strings.Contains(err.Error(), "PROXY_TOKEN") {
		t.Errorf("error should name the variable, got: %v", err)
	}
}

// The two audiences must not be interchangeable, or a ticket — which travels in a
// URL by construction — becomes a full API credential, or renews itself forever.
func TestTicketCannotReachTheAPIOrMintAnother(t *testing.T) {
	cfg := testConfig(t)
	cfg.AdminPassword = "hunter2"
	a, _ := open(t, &cfg)

	jwt, _, err := a.Login(cfg.AdminUser, cfg.AdminPassword, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ticket, ttl, err := a.Ticket(jwt)
	if err != nil {
		t.Fatalf("Ticket: %v", err)
	}
	if ttl != ticketTTL {
		t.Errorf("ttl = %s, want %s", ttl, ticketTTL)
	}

	if _, err := a.VerifyTicket(ticket); err != nil {
		t.Errorf("a fresh ticket failed stream verification: %v", err)
	}
	if _, err := a.VerifyAPI(ticket); err == nil {
		t.Error("a ticket was accepted as an API credential")
	}
	if _, _, err := a.Ticket(ticket); err == nil {
		t.Error("a ticket minted another ticket")
	}

	// The reverse is allowed on purpose: curl -N with a Bearer header is how the
	// stream gets debugged.
	if _, err := a.VerifyAPI(jwt); err != nil {
		t.Errorf("an API JWT was rejected by the API: %v", err)
	}
	if _, err := a.VerifyTicket(jwt); err == nil {
		t.Error("an API JWT passed ticket verification")
	}
}

// A token is not a browser session and a browser session is not a proxy licence.
func TestCredentialKindsDoNotCrossOver(t *testing.T) {
	cfg := testConfig(t)
	cfg.AdminPassword = "hunter2"
	a, _ := open(t, &cfg)

	jwt, _, err := a.Login(cfg.AdminUser, cfg.AdminPassword, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyProxy(jwt); err == nil {
		t.Error("an operator JWT was accepted as a proxy credential")
	}

	secret, _, err := a.Mint("api-caller", ScopeAdmin)
	if err != nil {
		t.Fatal(err)
	}
	// An admin token is valid on the API and on the proxy; that is what the
	// scope means.
	if _, err := a.VerifyAPI(secret); err != nil {
		t.Errorf("an admin token was rejected by the API: %v", err)
	}
	if _, err := a.VerifyProxy(secret); err != nil {
		t.Errorf("an admin token was rejected by the proxy: %v", err)
	}
	if _, err := a.VerifyTicket(secret); err == nil {
		t.Error("a token passed ticket verification")
	}
}

func TestScopesGateWhatTheyShould(t *testing.T) {
	proxy := Identity{Scope: ScopeProxy}
	admin := Identity{Scope: ScopeAdmin}

	if !proxy.Allows(ScopeProxy) {
		t.Error("a proxy identity should allow the proxy scope")
	}
	if proxy.Allows(ScopeAdmin) {
		t.Error("a proxy identity must not allow the admin scope")
	}
	if !admin.Allows(ScopeAdmin) || !admin.Allows(ScopeProxy) {
		t.Error("an admin identity should allow everything")
	}
	if (Identity{}).Allows(ScopeProxy) {
		t.Error("a zero identity must allow nothing")
	}
}

func TestGarbageIsNeverAccepted(t *testing.T) {
	cfg := testConfig(t)
	a, _ := open(t, &cfg)

	for _, secret := range []string{
		"", "x", tokenPrefix, tokenPrefix + "short",
		tokenPrefix + strings.Repeat("A", 22), // right shape, never issued
		strings.Repeat("A", maxJWTLen*2),
	} {
		if _, err := a.VerifyProxy(secret); err == nil {
			t.Errorf("VerifyProxy accepted %q", secret)
		}
		if _, err := a.VerifyAPI(secret); err == nil {
			t.Errorf("VerifyAPI accepted %q", secret)
		}
	}
}

func TestFlushPersistsLastUse(t *testing.T) {
	cfg := testConfig(t)
	a, _ := open(t, &cfg)

	secret, info, err := a.Mint("scraper", ScopeProxy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyProxy(secret); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	restarted, _ := open(t, &cfg)
	for _, got := range restarted.List() {
		if got.ID != info.ID {
			continue
		}
		if got.LastUsed == 0 {
			t.Error("last use was not persisted")
		}
		return
	}
	t.Fatalf("token %s is missing after a restart", info.ID)
}

// The hot path must not need the store's lock: it sits behind an fsync, and
// invariant 14 says nothing on a request path may block. Run with -race, this
// also proves the atomic last-use stamp is clean against a concurrent flush.
func TestVerifyIsSafeAlongsideMutations(t *testing.T) {
	cfg := testConfig(t)
	a, _ := open(t, &cfg)

	secret, _, err := a.Mint("steady", ScopeProxy)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := a.VerifyProxy(secret); err != nil {
				t.Errorf("the steady token was rejected mid-mutation: %v", err)
				return
			}
		}
	}()

	for i := range 20 {
		_, info, err := a.Mint("churn", ScopeProxy)
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if err := a.Revoke(info.ID); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}

// AUTH_DISABLED has to be answered at every entry point, not just the one a
// reader happens to check. A verifier that still refused on any of these would
// leave the pool half-open, and which half depends on which listener you use.
func TestDisabledAuthAcceptsEveryCredentialPath(t *testing.T) {
	cfg := testConfig(t)
	cfg.AuthDisabled = true
	a, _ := open(t, &cfg)

	if !a.Disabled() {
		t.Fatal("Disabled() = false with AuthDisabled set")
	}

	for name, verify := range map[string]func(string) (Identity, error){
		"proxy":  a.VerifyProxy,
		"api":    a.VerifyAPI,
		"ticket": a.VerifyTicket,
	} {
		// An empty credential is the case that matters: it is what a caller that
		// was never configured with one actually sends.
		for _, presented := range []string{"", "nonsense", "tp_notAToken"} {
			id, err := verify(presented)
			if err != nil {
				t.Errorf("%s(%q) = %v, want no error", name, presented, err)
				continue
			}
			// Admin, because Allows treats it as covering every scope and a
			// disabled check must satisfy the proxy-scoped routes too.
			if id.Scope != ScopeAdmin {
				t.Errorf("%s(%q) scope = %q, want %q", name, presented, id.Scope, ScopeAdmin)
			}
			if !id.Allows(ScopeProxy) || !id.Allows(ScopeAdmin) {
				t.Errorf("%s(%q) identity %+v does not allow both scopes", name, presented, id)
			}
		}
	}

	// A ticket must still be mintable without a bearer, or the dashboard's stream
	// cannot open: the stream handler mints one before it connects.
	if _, _, err := a.Ticket(""); err != nil {
		t.Errorf("Ticket with no bearer = %v, want a ticket", err)
	}
	if _, _, err := a.Login("nobody", "wrong", "10.0.0.1"); err != nil {
		t.Errorf("Login with wrong credentials = %v, want success", err)
	}
}

// Turning authentication off must not throw away the credentials, or unsetting
// the flag becomes a second setup step: no password to sign in with, and on a
// store that is no longer fresh, no bootstrap token either.
func TestDisabledAuthStillProvisionsCredentialsForLater(t *testing.T) {
	cfg := testConfig(t)
	cfg.AuthDisabled = true
	a, boot := open(t, &cfg)

	if boot.AdminPassword == "" || boot.ProxyToken == "" {
		t.Fatalf("boot = %+v, want both credentials generated", boot)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}

	// The same data directory, with the flag cleared: what an operator sees after
	// removing AUTH_DISABLED and restarting.
	cfg.AuthDisabled = false
	reopened, _ := open(t, &cfg)

	if _, _, err := reopened.Login(cfg.AdminUser, boot.AdminPassword, "10.0.0.1"); err != nil {
		t.Errorf("the password logged while auth was off does not work once it is on: %v", err)
	}
	if _, err := reopened.VerifyProxy(boot.ProxyToken); err != nil {
		t.Errorf("the bootstrap token logged while auth was off is not accepted: %v", err)
	}
	if _, err := reopened.VerifyProxy("tp_definitelyNotTheToken"); err == nil {
		t.Error("clearing AUTH_DISABLED left the pool open")
	}
}
