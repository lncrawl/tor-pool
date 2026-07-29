// Package auth owns every credential torpool checks: the operator's login, the
// JWT it is exchanged for, the short-lived ticket that carries it onto the SSE
// stream, and the tokens that authorise proxy traffic and API calls.
//
// AUTH_DISABLED turns all of it off, for a pool reachable only from the machine
// it runs on. Every guarantee in this package is therefore conditional on that
// flag being unset, which is why the disabled path is one branch at the top of
// each Verify method rather than a permissive verifier injected somewhere: the
// condition has to be visible at every point it applies, and reading any of them
// has to be enough to know the whole story.
//
// The flag is answered once, in Disabled, and the listeners ask before they
// challenge — a credential check that simply always returned nil would not be
// enough, because SOCKS5 refuses a client offering no authentication method and
// the HTTP proxy answers 407 before it looks at anything.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lncrawl/tor-pool/internal/config"
	"github.com/lncrawl/tor-pool/internal/stats"
)

const (
	// ticketTTL is how long an SSE ticket lives: long enough for a browser to
	// open the stream, short enough that one captured from an access log, a
	// Referer header or browser history is already dead.
	ticketTTL = 60 * time.Second

	// flushInterval is how often last-use stamps reach the disk.
	flushInterval = time.Minute

	// maxLoginKeys bounds the login limiter's table. Its keys are remote
	// addresses, so untrusted input decides how many there are.
	maxLoginKeys = 4096

	// maxTokenNameLen keeps an operator-supplied label from becoming a payload.
	maxTokenNameLen = 64

	// adminPasswordBytes is the size of a generated admin password. 128 bits is
	// what makes storing its digest safe, since it is not a dictionary target.
	adminPasswordBytes = 16
)

// Errors callers are expected to distinguish. Everything else is wrapped.
var (
	// ErrUnauthorized is a missing, malformed or unrecognised credential. The
	// reason is deliberately not narrowed: reporting which half of a login was
	// wrong is an oracle.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrExpired is a well-formed credential that has aged out. Kept separate
	// from ErrUnauthorized because a client can act on it, by logging in again.
	ErrExpired = errors.New("credential expired")

	// ErrForbidden is a valid credential without the scope for what it asked.
	ErrForbidden = errors.New("forbidden")

	// ErrRateLimited is too many failed logins from one address.
	ErrRateLimited = errors.New("too many attempts")

	// ErrNoSuchToken is a revoke for an id that is not there.
	ErrNoSuchToken = errors.New("no such token")

	// ErrEnvToken is an attempt to revoke the token supplied through
	// PROXY_TOKEN, which is configuration and changes by restart.
	ErrEnvToken = errors.New("token comes from the environment")
)

// Identity is a verified caller.
type Identity struct {
	// TokenID is empty when the caller is the operator rather than a token.
	TokenID string
	Name    string
	Scope   Scope
}

// Allows reports whether this identity carries the scope a route requires.
func (i Identity) Allows(need Scope) bool {
	return i.Scope == ScopeAdmin || i.Scope == need
}

// Bootstrap reports credentials generated during this boot so the caller can
// print them exactly once. An empty field means the credential came from
// configuration or from a previous boot.
type Bootstrap struct {
	AdminUser     string
	AdminPassword string
	ProxyToken    string
}

// Any reports whether anything was generated and needs showing.
func (b Bootstrap) Any() bool { return b.AdminPassword != "" || b.ProxyToken != "" }

// anonymous is who every caller is when authentication is disabled.
//
// Admin scope, because a disabled check has to satisfy both scopes and Allows
// treats admin as covering everything. The name is what the audit log and the
// dashboard show, and it is deliberately not a real account: nothing was
// verified, and a display name of "admin" would imply otherwise.
var anonymous = Identity{Name: "anonymous", Scope: ScopeAdmin}

// Auth verifies credentials and issues them.
type Auth struct {
	store  *store
	events *stats.EventLog
	log    *slog.Logger

	// disabled is AUTH_DISABLED. Read on the hot path, so it stays a plain field
	// set once in Open and never written again.
	disabled bool

	// index is an immutable map, replaced wholesale on every change so that
	// verification never takes a lock. Invariant 14: nothing on a request path
	// may block, and waiting on the store's mutex means waiting behind an fsync.
	index atomic.Pointer[map[[32]byte]*Token]

	// envToken is PROXY_TOKEN. Verified like any other token but never
	// persisted: the environment is authoritative and changes by restart, so
	// seeding it into the store would leave a stale value working.
	envToken *Token

	jwtKey    []byte
	loginTTL  time.Duration
	adminUser string

	// adminDigest is the SHA-256 of the effective password, held in memory. It
	// reaches the disk only when torpool generated the password itself.
	adminDigest [32]byte

	// pv is the password version stamped into every JWT, so changing the
	// password invalidates outstanding ones without storing a verifier.
	pv string

	logins *limiter
}

// Open loads the credential store and resolves the operator's credentials,
// generating whatever is missing.
//
// Called before the fleet starts, so a data directory that cannot be written
// fails immediately rather than after a two-minute tor bootstrap.
func Open(cfg *config.Config, events *stats.EventLog, log *slog.Logger) (*Auth, Bootstrap, error) {
	st, err := openStore(cfg.DataDir)
	if err != nil {
		return nil, Bootstrap{}, err
	}

	a := &Auth{
		store:     st,
		events:    events,
		log:       log,
		disabled:  cfg.AuthDisabled,
		loginTTL:  cfg.LoginTTL,
		adminUser: cfg.AdminUser,
		logins:    newLimiter(cfg.LoginRateLimit, time.Minute, maxLoginKeys),
	}

	boot := Bootstrap{AdminUser: cfg.AdminUser}
	if err := st.mutate(func(f *file) (bool, error) {
		changed := false

		if f.JWTKey == "" {
			key, err := randomHex(jwtKeyBytes)
			if err != nil {
				return false, err
			}
			f.JWTKey = key
			changed = true
		}
		key, err := hex.DecodeString(f.JWTKey)
		if err != nil || len(key) < jwtKeyBytes {
			return false, fmt.Errorf("stored signing key is malformed or too short")
		}
		a.jwtKey = key

		switch {
		case cfg.AdminPassword != "":
			a.adminDigest = sha256.Sum256([]byte(cfg.AdminPassword))
			// Drop any previously generated digest: removing ADMIN_PASSWORD from
			// the environment should mint a fresh password, not silently fall
			// back to whatever was last generated.
			if f.AdminDigest != "" {
				f.AdminDigest = ""
				changed = true
			}

		case f.AdminDigest != "":
			d, err := hex.DecodeString(f.AdminDigest)
			if err != nil || len(d) != sha256.Size {
				return false, fmt.Errorf("stored admin digest is malformed")
			}
			copy(a.adminDigest[:], d)

		default:
			pw, err := randomHex(adminPasswordBytes)
			if err != nil {
				return false, err
			}
			boot.AdminPassword = pw
			a.adminDigest = sha256.Sum256([]byte(pw))
			f.AdminDigest = hex.EncodeToString(a.adminDigest[:])
			changed = true
		}

		// A first boot with no configured token mints one, so the proxy is
		// usable without opening the dashboard. An empty token list on a store
		// that already exists is the operator's choice and is left alone.
		if st.fresh && cfg.ProxyToken == "" && len(f.Tokens) == 0 {
			secret, t, err := buildToken("bootstrap", ScopeProxy)
			if err != nil {
				return false, err
			}
			boot.ProxyToken = secret
			f.Tokens = append(f.Tokens, t)
			changed = true
		}

		return changed, nil
	}); err != nil {
		return nil, Bootstrap{}, err
	}

	a.pv = passwordVersion(a.jwtKey, a.adminDigest)

	if cfg.ProxyToken != "" {
		// The prefix is load-bearing, not cosmetic: API dispatch tells a token
		// from a JWT by it, so one without it would be handed to the JWT parser
		// and never match anything. Refuse it loudly rather than silently.
		if !looksLikeToken(cfg.ProxyToken) {
			return nil, Bootstrap{}, fmt.Errorf("PROXY_TOKEN must start with %q", tokenPrefix)
		}
		digest := hashSecret(cfg.ProxyToken)
		a.envToken = &Token{
			ID:      "env",
			Name:    "PROXY_TOKEN",
			Scope:   ScopeProxy,
			Digest:  hex.EncodeToString(digest[:]),
			fromEnv: true,
		}
	}
	st.read(a.reindex)

	if a.disabled {
		// Credentials are still resolved and still generated above, on purpose.
		// Skipping that would make unsetting AUTH_DISABLED a second setup step —
		// no admin password to log in with and, on a store that is no longer
		// fresh, no bootstrap token either. They sit unused instead, and the
		// startup banner says as much.
		a.log.Warn("authentication is disabled by AUTH_DISABLED",
			"proxy", "any connection is accepted",
			"api", "any request is answered")
		a.event("authentication disabled",
			"AUTH_DISABLED is set; the proxy and the API accept any caller")
	}

	return a, boot, nil
}

// Disabled reports whether AUTH_DISABLED switched every check off.
//
// The listeners need this and not just a permissive check: they challenge before
// they verify, and a challenge nobody can answer is still a closed door.
func (a *Auth) Disabled() bool { return a.disabled }

// Run flushes last-use stamps on a ticker until ctx is cancelled.
//
// The final flush is the caller's, so it can be ordered ahead of the fleet
// shutdown: a slow tor exit would otherwise eat the window.
func (a *Auth) Run(ctx context.Context) {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.Flush(); err != nil {
				a.log.Error("flush token usage", "error", err)
			}
		}
	}
}

// Flush folds last-use stamps from the hot path into the store, writing only
// when something moved so a busy pool does not dirty the file every minute.
func (a *Auth) Flush() error {
	return a.store.mutate(func(f *file) (bool, error) {
		changed := false
		for _, t := range f.Tokens {
			if u := t.used.Load(); u > t.LastUsed {
				t.LastUsed = u
				changed = true
			}
		}
		return changed, nil
	})
}

// VerifyProxy checks a proxy password.
//
// Tokens only. An operator JWT is a session credential for the API, not a licence
// to move bytes, and keeping the two apart means a browser session cannot be
// replayed onto the proxy port.
func (a *Auth) VerifyProxy(secret string) (Identity, error) {
	if a.disabled {
		return anonymous, nil
	}
	t := a.lookup(secret)
	if t == nil {
		return Identity{}, ErrUnauthorized
	}
	return Identity{TokenID: t.ID, Name: t.Name, Scope: t.Scope}, nil
}

// CheckProxy verifies a proxy password.
//
// Shaped as a plain error-returning function so internal/proxy can declare what it
// needs as a func type and import nothing from here, the same way it declares its
// own Router rather than importing the pool.
func (a *Auth) CheckProxy(secret string) error {
	_, err := a.VerifyProxy(secret)
	return err
}

// VerifyAPI checks a bearer credential for the REST API: either the operator's
// JWT or a token.
//
// Dispatch is on the token prefix rather than "try a JWT, then try a token",
// which would misclassify anything with two dots and report whichever error was
// less wrong.
func (a *Auth) VerifyAPI(bearer string) (Identity, error) {
	if a.disabled {
		return anonymous, nil
	}
	if looksLikeToken(bearer) {
		return a.VerifyProxy(bearer)
	}
	// audAPI only, so a stream ticket is refused here. Without that a ticket —
	// which travels in a URL by construction — would be a full API credential.
	c, err := verifyJWT(a.jwtKey, bearer, audAPI, a.adminUser, a.pv)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Name: c.Sub, Scope: ScopeAdmin}, nil
}

// VerifyTicket checks an SSE ticket taken from a query string.
//
// The audience is the whole boundary here: nothing but the stream route calls
// this, and VerifyAPI refuses audStream, so the returned scope is never consulted
// for an authorisation decision.
func (a *Auth) VerifyTicket(ticket string) (Identity, error) {
	if a.disabled {
		return anonymous, nil
	}
	c, err := verifyJWT(a.jwtKey, ticket, audStream, a.adminUser, a.pv)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Name: c.Sub, Scope: ScopeAdmin}, nil
}

// Login exchanges the operator's credentials for an API JWT and its expiry.
func (a *Auth) Login(user, password, remote string) (token string, expires time.Time, err error) {
	if a.disabled {
		// Succeeds whatever was posted, and is not rate limited: there is no
		// secret to guess, so a limiter would only lock an operator out of an
		// endpoint that refuses nobody. The dashboard skips the screen entirely,
		// but a script that logs in must not get a 401 from a pool advertising
		// that it needs no credential.
		return a.issue(a.adminUser, remote)
	}
	if blocked, retry := a.logins.blocked(remote); blocked {
		a.event("login refused, too many attempts", remote)
		return "", time.Time{}, fmt.Errorf("%w: retry in %s", ErrRateLimited, retry.Round(time.Second))
	}

	// Both halves are always compared and the results combined, so response time
	// cannot reveal whether the username was right. Digests rather than the raw
	// strings, because subtle.ConstantTimeCompare returns early when lengths
	// differ and would leak the password's length.
	gotUser := sha256.Sum256([]byte(user))
	wantUser := sha256.Sum256([]byte(a.adminUser))
	gotPass := sha256.Sum256([]byte(password))
	ok := subtle.ConstantTimeCompare(gotUser[:], wantUser[:]) &
		subtle.ConstantTimeCompare(gotPass[:], a.adminDigest[:])
	if ok != 1 {
		a.logins.fail(remote)
		a.event("failed login", remote)
		return "", time.Time{}, ErrUnauthorized
	}
	a.logins.succeed(remote)
	return a.issue(a.adminUser, remote)
}

// issue signs an API JWT for a caller whose credentials have already been
// settled, one way or the other.
func (a *Auth) issue(sub, remote string) (token string, expires time.Time, err error) {
	now := time.Now()
	expires = now.Add(a.loginTTL)
	token, err = signJWT(a.jwtKey, claims{
		Iss: jwtIssuer,
		Sub: sub,
		Aud: audAPI,
		Iat: now.Unix(),
		Exp: expires.Unix(),
		PV:  a.pv,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	a.event("operator signed in", remote)
	return token, expires, nil
}

// Ticket mints a short-lived stream credential from a valid API JWT.
func (a *Auth) Ticket(bearer string) (ticket string, ttl time.Duration, err error) {
	// Deliberately not VerifyAPI. A ticket must not mint another ticket, or a
	// captured one renews itself indefinitely and its lifetime means nothing. A
	// token is refused too: a programmatic caller can read /api/stream with its
	// own header and has no need for a URL credential.
	sub := a.adminUser
	if !a.disabled {
		c, err := verifyJWT(a.jwtKey, bearer, audAPI, a.adminUser, a.pv)
		if err != nil {
			return "", 0, err
		}
		sub = c.Sub
	}
	now := time.Now()
	ticket, err = signJWT(a.jwtKey, claims{
		Iss: jwtIssuer,
		Sub: sub,
		Aud: audStream,
		Iat: now.Unix(),
		Exp: now.Add(ticketTTL).Unix(),
		PV:  a.pv,
	})
	if err != nil {
		return "", 0, err
	}
	return ticket, ticketTTL, nil
}

// Mint issues a token. The secret is returned once here and never stored.
func (a *Auth) Mint(name string, scope Scope) (secret string, info TokenInfo, err error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", TokenInfo{}, errors.New("token name is required")
	case len(name) > maxTokenNameLen:
		return "", TokenInfo{}, fmt.Errorf("token name must be at most %d characters", maxTokenNameLen)
	case !scope.Valid():
		return "", TokenInfo{}, fmt.Errorf("scope must be %q or %q", ScopeProxy, ScopeAdmin)
	}

	secret, t, err := buildToken(name, scope)
	if err != nil {
		return "", TokenInfo{}, err
	}
	if err := a.store.mutate(func(f *file) (bool, error) {
		f.Tokens = append(f.Tokens, t)
		a.reindex(f)
		return true, nil
	}); err != nil {
		return "", TokenInfo{}, err
	}

	a.event("token issued", fmt.Sprintf("%s (%s), scope %s", t.Name, t.ID, t.Scope))
	return secret, t.info(), nil
}

// Revoke deletes a token. It stops working immediately, whether or not the store
// can be written.
func (a *Auth) Revoke(id string) error {
	var revoked *Token

	err := a.store.mutate(func(f *file) (bool, error) {
		for i, t := range f.Tokens {
			if t.ID != id {
				continue
			}
			revoked = t
			f.Tokens = append(f.Tokens[:i], f.Tokens[i+1:]...)
			// The index is swapped before the file is written, on purpose. The
			// other order lets a failed write answer 200 while the token keeps
			// working until the next restart.
			a.reindex(f)
			return true, nil
		}
		if a.envToken != nil && a.envToken.ID == id {
			return false, ErrEnvToken
		}
		return false, ErrNoSuchToken
	})

	if revoked != nil {
		a.event("token revoked", fmt.Sprintf("%s (%s)", revoked.Name, revoked.ID))
	}
	return err
}

// List reports every token, secrets excluded.
func (a *Auth) List() []TokenInfo {
	out := make([]TokenInfo, 0, 4)
	if a.envToken != nil {
		out = append(out, a.envToken.info())
	}
	a.store.read(func(f *file) {
		for _, t := range f.Tokens {
			out = append(out, t.info())
		}
	})
	return out
}

// lookup resolves a secret to its token and stamps its last use.
//
// This is the hot path — every SOCKS connection and every proxied HTTP request.
// One SHA-256 over 25 bytes and one read of an immutable map: no lock, no
// allocation, no syscall. Go's map lookup is not constant-time, but its input
// here is already a digest, so bucket timing cannot be walked back toward a
// secret. That stops being true the moment anyone "optimises" this by comparing a
// stored plaintext prefix first.
func (a *Auth) lookup(secret string) *Token {
	if !looksLikeToken(secret) {
		return nil
	}
	m := a.index.Load()
	if m == nil {
		return nil
	}
	t := (*m)[hashSecret(secret)]
	if t == nil {
		return nil
	}
	t.used.Store(time.Now().Unix())
	return t
}

// reindex rebuilds the lookup map and swaps it in. Called with the store's lock
// held; it only stores a pointer, so it cannot block.
//
// The map holds the store's own *Token pointers, which is what lets a pending
// last-use stamp survive an unrelated token being revoked.
func (a *Auth) reindex(f *file) {
	m := make(map[[32]byte]*Token, len(f.Tokens)+1)
	add := func(t *Token) {
		d, err := hex.DecodeString(t.Digest)
		if err != nil || len(d) != sha256.Size {
			a.log.Error("ignoring token with an unreadable digest", "token", t.ID)
			return
		}
		var key [32]byte
		copy(key[:], d)
		m[key] = t
	}
	for _, t := range f.Tokens {
		add(t)
	}
	if a.envToken != nil {
		add(a.envToken)
	}
	a.index.Store(&m)
}

// event records an operator action in the audit log.
//
// Only operator actions belong here. A rejected *proxy* credential is logged to
// stderr instead: the event ring holds a couple of thousand entries, so one entry
// per refused connection would let anyone flush the entire audit history in
// seconds — precisely when it is worth reading — and every rejection would
// serialise through the mutex the dashboard streams through.
func (a *Auth) event(message, detail string) {
	if a.events == nil {
		return
	}
	a.events.Add(stats.Event{Type: stats.EventAuth, Message: message, Detail: detail})
}

// buildToken generates a secret and the record that will verify it.
func buildToken(name string, scope Scope) (secret string, t *Token, err error) {
	secret, err = newSecret()
	if err != nil {
		return "", nil, err
	}
	id, err := newID()
	if err != nil {
		return "", nil, err
	}
	digest := hashSecret(secret)
	return secret, &Token{
		ID:        id,
		Name:      name,
		Scope:     scope,
		Digest:    hex.EncodeToString(digest[:]),
		CreatedAt: time.Now().Unix(),
	}, nil
}
