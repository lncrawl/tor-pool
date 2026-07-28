package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// The tests below are the reason a hand-written JWT is defensible. Each one is a
// published attack on an implementation that took a shortcut, so deleting any of
// them removes the evidence that the shortcut is absent.

var testKey = []byte("0123456789abcdef0123456789abcdef")

const (
	testSub = "admin"
	testPV  = "pv-fixture"
)

func validClaims() claims {
	now := time.Now()
	return claims{
		Iss: jwtIssuer,
		Sub: testSub,
		Aud: audAPI,
		Iat: now.Unix(),
		Exp: now.Add(time.Hour).Unix(),
		PV:  testPV,
	}
}

func mustSign(t *testing.T, c claims) string {
	t.Helper()
	token, err := signJWT(testKey, c)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	return token
}

// reassemble rebuilds a token from parts and re-signs it with testKey, so a test
// can change the header or payload and still present a signature that is valid
// for what it sent. Anything that survives this is trusting the payload.
func reassemble(header, payload string) string {
	signing := header + "." + payload
	return signing + "." + base64.RawURLEncoding.EncodeToString(macOf(testKey, signing))
}

func verify(token string) (claims, error) {
	return verifyJWT(testKey, token, audAPI, testSub, testPV)
}

func TestJWTRoundTrips(t *testing.T) {
	want := validClaims()
	got, err := verify(mustSign(t, want))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != want {
		t.Errorf("claims = %+v, want %+v", got, want)
	}
}

// The single most important test in the file. An implementation that reads "alg"
// to pick a verifier accepts this.
func TestJWTRejectsAlgNone(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(validClaims())
	if err != nil {
		t.Fatal(err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)

	// Both shapes an alg:none forgery takes: no signature at all, and a
	// signature that is genuinely valid for this header.
	for name, token := range map[string]string{
		"empty signature": header + "." + body + ".",
		"signed":          reassemble(header, body),
	} {
		if _, err := verify(token); err == nil {
			t.Errorf("%s: alg:none was accepted", name)
		}
	}
}

// A correctly signed token whose header claims a different algorithm. Rejected
// because the header must match byte for byte, not because HS384 is enumerated.
func TestJWTRejectsAlgSubstitution(t *testing.T) {
	for _, alg := range []string{"HS384", "HS512", "RS256", "hs256"} {
		header := base64.RawURLEncoding.EncodeToString(
			[]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
		payload, err := json.Marshal(validClaims())
		if err != nil {
			t.Fatal(err)
		}
		token := reassemble(header, base64.RawURLEncoding.EncodeToString(payload))
		if _, err := verify(token); err == nil {
			t.Errorf("alg %q was accepted", alg)
		}
	}
}

func TestJWTRejectsMalformedStructure(t *testing.T) {
	valid := mustSign(t, validClaims())
	parts := strings.Split(valid, ".")

	for name, token := range map[string]string{
		"empty":            "",
		"one segment":      parts[0],
		"two segments":     parts[0] + "." + parts[1],
		"four segments":    valid + "." + parts[2],
		"empty header":     "." + parts[1] + "." + parts[2],
		"empty payload":    parts[0] + ".." + parts[2],
		"empty signature":  parts[0] + "." + parts[1] + ".",
		"leading dot":      "." + valid,
		"just separators":  "..",
		"not base64":       "!!!.???.***",
		"payload not json": reassemble(parts[0], base64.RawURLEncoding.EncodeToString([]byte("nope"))),
	} {
		if _, err := verify(token); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Padded base64 must not decode, or two distinct token strings map to one set of
// claims and any replay cache keyed on the string is bypassable.
func TestJWTRejectsPaddedBase64(t *testing.T) {
	parts := strings.Split(mustSign(t, validClaims()), ".")

	for name, token := range map[string]string{
		"padded signature": parts[0] + "." + parts[1] + "." + parts[2] + "=",
		"padded payload":   parts[0] + "." + parts[1] + "=." + parts[2],
	} {
		if _, err := verify(token); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestJWTRejectsTampering(t *testing.T) {
	valid := mustSign(t, validClaims())
	parts := strings.Split(valid, ".")

	// A payload edited without re-signing.
	forged := validClaims()
	forged.Sub = "root"
	payload, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	swapped := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]
	if _, err := verify(swapped); err == nil {
		t.Error("a payload swapped under an old signature was accepted")
	}

	// A flipped bit in the signature.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0x01
	flipped := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := verify(flipped); err == nil {
		t.Error("a corrupted signature was accepted")
	}

	// A truncated signature. hmac.Equal is length-sensitive; a prefix compare
	// would let this through.
	short := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig[:16])
	if _, err := verify(short); err == nil {
		t.Error("a truncated signature was accepted")
	}
}

func TestJWTRejectsAnotherKey(t *testing.T) {
	other := []byte("fedcba9876543210fedcba9876543210")
	token, err := signJWT(other, validClaims())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(token); err == nil {
		t.Error("a token signed with a different key was accepted")
	}
}

// An absent exp must be a rejection, never treated as "no expiry".
func TestJWTRejectsMissingExpiry(t *testing.T) {
	c := validClaims()
	c.Exp = 0
	if _, err := verify(mustSign(t, c)); !errors.Is(err, ErrExpired) {
		t.Errorf("error = %v, want ErrExpired", err)
	}
}

func TestJWTReportsExpiryDistinctly(t *testing.T) {
	c := validClaims()
	c.Exp = time.Now().Add(-time.Second).Unix()
	// Distinguished from a bad signature on purpose: a client can act on
	// "expired" by logging in again, and it reveals nothing a valid holder of the
	// token did not already know.
	if _, err := verify(mustSign(t, c)); !errors.Is(err, ErrExpired) {
		t.Errorf("error = %v, want ErrExpired", err)
	}
}

func TestJWTRejectsMismatchedClaims(t *testing.T) {
	cases := map[string]func(*claims){
		"wrong issuer":   func(c *claims) { c.Iss = "someone-else" },
		"empty issuer":   func(c *claims) { c.Iss = "" },
		"wrong audience": func(c *claims) { c.Aud = audStream },
		"empty audience": func(c *claims) { c.Aud = "" },
		"wrong subject":  func(c *claims) { c.Sub = "root" },
		"empty subject":  func(c *claims) { c.Sub = "" },
		// A stale password version is how a password change invalidates every
		// outstanding JWT without storing a verifier for the password.
		"stale password version": func(c *claims) { c.PV = "pv-old" },
		"empty password version": func(c *claims) { c.PV = "" },
		// Issued well into the future, beyond the skew allowance.
		"issued in the future": func(c *claims) { c.Iat = time.Now().Add(time.Hour).Unix() },
	}
	for name, mangle := range cases {
		c := validClaims()
		mangle(&c)
		if _, err := verify(mustSign(t, c)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The length check must come before any decoding, so an unauthenticated caller
// cannot make the process parse megabytes.
func TestJWTRejectsOversizedInput(t *testing.T) {
	if _, err := verify(strings.Repeat("a", maxJWTLen+1)); err == nil {
		t.Error("an oversized token was accepted")
	}
}

// The audiences must not be interchangeable in either direction; see the
// asymmetry tests in auth_test.go for why the reverse is deliberately allowed.
func TestJWTAudiencesAreDistinct(t *testing.T) {
	c := validClaims()
	c.Aud = audStream
	token := mustSign(t, c)

	if _, err := verifyJWT(testKey, token, audAPI, testSub, testPV); err == nil {
		t.Error("a stream ticket passed as an API credential")
	}
	if _, err := verifyJWT(testKey, token, audStream, testSub, testPV); err != nil {
		t.Errorf("a stream ticket failed stream verification: %v", err)
	}
}

func TestPasswordVersionIsKeyedAndStable(t *testing.T) {
	digest := sha256.Sum256([]byte("hunter2"))
	first := passwordVersion(testKey, digest)
	if first != passwordVersion(testKey, digest) {
		t.Error("passwordVersion is not stable for the same inputs")
	}

	other := sha256.Sum256([]byte("hunter3"))
	if passwordVersion(testKey, other) == first {
		t.Error("a different password produced the same version")
	}
	if passwordVersion([]byte("fedcba9876543210fedcba9876543210"), digest) == first {
		t.Error("a different signing key produced the same version")
	}

	// Keyed rather than a bare digest, so the value on the wire cannot be
	// dictionary-attacked back to the password.
	bare := sha256.Sum256(digest[:])
	if first == base64.RawURLEncoding.EncodeToString(bare[:8]) {
		t.Error("passwordVersion is an unkeyed digest")
	}
	if !hmac.Equal([]byte(first), []byte(passwordVersion(testKey, digest))) {
		t.Error("passwordVersion disagreed with itself")
	}
}
