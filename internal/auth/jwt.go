package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// JWT is hand-written here for the same reason the SOCKS5 handshake and the
// Prometheus exposition are: HS256 over claims this process both issues and
// verifies is a few dozen lines of standard library, and the alternative is the
// module's first third-party dependency.
//
// That trade is only sound because of the rules in verifyJWT. Read them before
// touching anything in this file.

const (
	jwtIssuer = "tor-pool"

	// audAPI authenticates the REST API and the dashboard. audStream is minted
	// only for the SSE query string, because EventSource cannot send a header.
	audAPI    = "api"
	audStream = "stream"

	// jwtHeaderJSON is emitted verbatim and required verbatim. The "alg" field
	// is never read to choose a verifier.
	jwtHeaderJSON = `{"alg":"HS256","typ":"JWT"}`

	// maxJWTLen caps the work an unauthenticated caller can cause before any
	// credential has been checked. Our own tokens are a few hundred bytes.
	maxJWTLen = 4096

	// jwtKeyBytes is the HS256 signing key size. RFC 7518 §3.2 makes a key at
	// least as long as the hash output a MUST.
	jwtKeyBytes = 32

	// clockSkew tolerates a little drift when checking iat.
	clockSkew = 30 * time.Second
)

// jwtHeaderB64 is precomputed so verification is a string compare.
var jwtHeaderB64 = base64.RawURLEncoding.EncodeToString([]byte(jwtHeaderJSON))

// claims is the full payload. Every field is verified; none is decorative.
type claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`

	// PV binds a token to the admin password that was in force when it was
	// issued, so changing the password invalidates every outstanding JWT
	// immediately. It is a keyed digest rather than a stored verifier precisely
	// so that nothing derived from an operator-chosen password reaches the disk.
	PV string `json:"pv"`
}

// passwordVersion derives the pv claim from the signing key and the password
// digest. Keyed, so the value on the wire reveals nothing about the password.
func passwordVersion(key []byte, digest [32]byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(digest[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:8])
}

func signJWT(key []byte, c claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := jwtHeaderB64 + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signing + "." + base64.RawURLEncoding.EncodeToString(macOf(key, signing)), nil
}

func macOf(key []byte, signing string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signing))
	return mac.Sum(nil)
}

// verifyJWT checks a token against key and the expected audience, subject and
// password version, and returns its claims.
//
// The rules below are the ones hand-rolled implementations get wrong. Each one
// closes a published attack:
//
//   - The header's "alg" is never read to select a verifier. HMAC-SHA256 is
//     computed unconditionally and the header must equal jwtHeaderB64 byte for
//     byte, which kills "alg":"none" and every algorithm-substitution trick in
//     one check rather than one check per algorithm.
//   - The signature is verified before the payload is parsed, so no unverified
//     attacker input reaches json.Unmarshal.
//   - The signed input is the received text. Re-marshalling the claims and
//     verifying that would normalise attacker input and check a different string
//     than the one whose claims are then used.
//   - RawURLEncoding in both directions. Accepting padded base64 would let two
//     distinct token strings decode to one set of claims.
//   - An absent exp is a rejection. "No expiry" is never the answer.
func verifyJWT(key []byte, token, wantAud, wantSub, wantPV string) (claims, error) {
	var c claims

	if token == "" || len(token) > maxJWTLen {
		return c, ErrUnauthorized
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return c, ErrUnauthorized
	}
	if parts[0] != jwtHeaderB64 {
		return c, ErrUnauthorized
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, ErrUnauthorized
	}
	if !hmac.Equal(sig, macOf(key, parts[0]+"."+parts[1])) {
		return c, ErrUnauthorized
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, ErrUnauthorized
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, ErrUnauthorized
	}

	if c.Iss != jwtIssuer || c.Aud != wantAud || c.Sub != wantSub {
		return c, ErrUnauthorized
	}
	if c.PV != wantPV {
		// The admin password changed since this was issued.
		return c, ErrUnauthorized
	}
	now := time.Now()
	if c.Exp == 0 || !now.Before(time.Unix(c.Exp, 0)) {
		return c, ErrExpired
	}
	if c.Iat != 0 && now.Add(clockSkew).Before(time.Unix(c.Iat, 0)) {
		return c, ErrUnauthorized
	}
	return c, nil
}
