package auth

import (
	"crypto/rand"
	"crypto/sha256"
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

	// tokenChars is the length of a secret, excluding the prefix. 22 base62
	// characters is just over 130 bits, so the credential still carries the 128
	// bits its at-rest hashing assumes — see hashSecret, which is only sound
	// because there is nothing there to guess.
	tokenChars = 22

	// idChars is the length of the public identifier. It is not a secret and not
	// derived from one; the operator recognises tokens by name.
	idChars = 8
)

// base62Alphabet is what a generated credential is made of: digits and letters,
// nothing else.
//
// base64url would pack more bits per character, and its '-' and '_' are both
// legal in URL userinfo, so the original choice was not wrong on the wire. It was
// wrong everywhere else a token actually travels. Those two characters are what
// makes a token that a terminal word-breaks across a line, or that a
// double-click selects only half of, come back subtly different — and the failure
// then presents as a refused credential with no hint that the string was
// mangled in transit rather than wrong at the source. Alphanumeric costs nothing:
// the length is unchanged, because 22 characters of base62 still clears 128 bits.
const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

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
	s, err := randomBase62(tokenChars)
	if err != nil {
		return "", fmt.Errorf("generate token secret: %w", err)
	}
	return tokenPrefix + s, nil
}

// newID returns a fresh public identifier for a token.
func newID() (string, error) {
	s, err := randomBase62(idChars)
	if err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return s, nil
}

// randomBase62 returns n characters drawn uniformly from base62Alphabet.
//
// Rejection sampling rather than `b % 62`, which is the obvious implementation and
// is biased: 256 is not a multiple of 62, so the first eight characters of the
// alphabet would come up about 1.6% more often than the rest. The bias is small
// and it is measured in bits of a credential, which is the one place not to
// accept one.
func randomBase62(n int) (string, error) {
	// The largest multiple of 62 that fits in a byte. Values at or above it are
	// discarded rather than folded, because folding them is exactly the bias.
	const limit = 256 - 256%len(base62Alphabet)

	out := make([]byte, 0, n)
	// Drawn a bufferful at a time: a rejected byte would otherwise cost its own
	// read, and roughly one byte in 32 is rejected.
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, base62Alphabet[int(b)%len(base62Alphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
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
