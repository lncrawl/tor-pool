package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
)

const (
	// tokenPrefix lets the API middleware tell a token from a JWT structurally
	// instead of trying to parse both and reporting whichever error is less
	// misleading. It also makes a leaked token greppable by secret scanners, the
	// way ghp_ is.
	tokenPrefix = "tp_"

	// tokenBytes is 128 bits, which base64url renders in 22 characters — 25 with
	// the prefix. Every character is legal in URL userinfo, so a token never
	// needs percent-encoding in a proxy URL.
	tokenBytes = 16

	// idBytes is the length of the public identifier. It is not a secret and not
	// derived from one; the operator recognises tokens by name.
	idBytes = 6
)

// Scope is what a credential may do. There is no read-only tier: /metrics is
// public, which was the only thing one would have been for.
type Scope string

const (
	// ScopeProxy authorises proxy traffic, plus the session sub-routes a caller
	// uses to manage the sessions it created.
	ScopeProxy Scope = "proxy"
	// ScopeAdmin authorises everything, proxy traffic included.
	ScopeAdmin Scope = "admin"
)

// Valid reports whether s is a scope this build knows.
func (s Scope) Valid() bool { return s == ScopeProxy || s == ScopeAdmin }

// Token is an issued credential as stored. The secret is never kept — only its
// digest — which is why a token can be shown exactly once, at mint.
//
// Not copyable: used is an atomic. Report tokens as a TokenInfo instead.
type Token struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Scope     Scope  `json:"scope"`
	Digest    string `json:"digest"`
	CreatedAt int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used,omitempty"`

	// used receives last-use stamps from the hot path, where taking the store's
	// mutex is forbidden. The flush loop folds it into LastUsed under the lock,
	// so LastUsed itself is never written concurrently and stays safe to
	// marshal. Unexported, so encoding/json ignores it.
	used atomic.Int64

	// fromEnv marks a token supplied through PROXY_TOKEN. It is verified like
	// any other but never persisted and cannot be revoked through the API.
	fromEnv bool
}

// TokenInfo is a token as the API reports it, and never carries the secret.
type TokenInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Scope     Scope  `json:"scope"`
	Source    string `json:"source"`
	CreatedAt int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used,omitempty"`
}

func (t *Token) info() TokenInfo {
	source := "store"
	if t.fromEnv {
		source = "environment"
	}
	last := t.LastUsed
	if u := t.used.Load(); u > last {
		last = u
	}
	return TokenInfo{
		ID:        t.ID,
		Name:      t.Name,
		Scope:     t.Scope,
		Source:    source,
		CreatedAt: t.CreatedAt,
		LastUsed:  last,
	}
}

// hashSecret is both the at-rest form of a token and its lookup key.
//
// A plain unsalted SHA-256, not bcrypt or argon2, and that is a decision rather
// than an oversight. A KDF's cost buys resistance to *guessing*, and there is
// nothing to guess against 128 bits from crypto/rand; meanwhile this runs on
// every proxy connection and every proxied HTTP request, where a deliberately
// slow hash is a CPU-exhaustion vector reachable from an unauthenticated port
// (invariant 14). Two preconditions keep it correct, and both must hold:
//
//   - Tokens are generated here and never chosen by a human. A human-chosen
//     secret behind an unsalted fast hash is a rainbow-table target.
//   - There is no per-token salt, so one map lookup answers the question instead
//     of one hash per stored token per request.
func hashSecret(secret string) [32]byte { return sha256.Sum256([]byte(secret)) }

// looksLikeToken reports whether a bearer credential is one of ours rather than
// a JWT.
func looksLikeToken(s string) bool { return strings.HasPrefix(s, tokenPrefix) }

// newSecret returns a fresh token secret.
func newSecret() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token secret: %w", err)
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// newID returns a fresh public identifier for a token.
func newID() (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randomHex returns n cryptographically random bytes as hex, for the signing key
// and the generated admin password.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return hex.EncodeToString(b), nil
}
