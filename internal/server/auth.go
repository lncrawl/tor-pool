package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/lncrawl/tor-pool/internal/auth"
)

// maxCredentialBody bounds the two endpoints that accept a body from a caller who
// may not be authenticated yet.
const maxCredentialBody = 4 << 10

// guard wraps a handler with the check its route declared.
//
// A route with no scope is public, and only /health, /metrics and the login
// endpoint may be — see routes().
func (s *Server) guard(rt route) http.HandlerFunc {
	if rt.need == "" {
		return rt.handler
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// EventSource cannot send an Authorization header, so the stream route
		// also accepts a short-lived ticket from the query string. A Bearer
		// header still works there, which is how `curl -N` debugs it.
		if rt.ticket {
			if t := r.URL.Query().Get("ticket"); t != "" {
				if _, err := s.auth.VerifyTicket(t); err != nil {
					writeUnauthorized(w, err)
					return
				}
				rt.handler(w, r)
				return
			}
		}

		id, err := s.auth.VerifyAPI(bearerToken(r))
		if err != nil {
			writeUnauthorized(w, err)
			return
		}
		if !id.Allows(rt.need) {
			// Deliberately no WWW-Authenticate on a 403. A client that sees one
			// retries, and there is nothing to retry with: the credential is
			// valid and merely insufficient. It is also why the dashboard signs
			// out on a 401 but never on a 403.
			http.Error(w, "insufficient scope", http.StatusForbidden)
			return
		}
		rt.handler(w, r)
	}
}

// bearerToken extracts the credential from an Authorization header. The scheme is
// case-insensitive per RFC 9110 §11.1.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	scheme, value, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

// writeUnauthorized answers a missing, malformed or expired credential.
//
// WWW-Authenticate is a MUST on a 401 (RFC 9110 §15.5.2). The description
// separates an expired credential — which a client can act on by logging in
// again, and which reveals nothing its holder did not already know — from
// everything else, which stays opaque.
func writeUnauthorized(w http.ResponseWriter, err error) {
	description := "invalid_token"
	if errors.Is(err, auth.ErrExpired) {
		description = "expired_token"
	}
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf("Bearer realm=%q, error=%q", "tor-pool", description))
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// authStatus tells an unauthenticated client what it is dealing with.
type authStatus struct {
	// Required is false when AUTH_DISABLED is set. The dashboard renders its app
	// directly rather than a sign-in screen, and a scripted caller can tell a
	// deliberately open pool from one whose credential it has got wrong.
	Required bool `json:"required"`
	// User is the operator name the login endpoint expects, so the sign-in form
	// can prefill it instead of guessing "admin" when ADMIN_USER says otherwise.
	// Not a secret: it is half of a credential whose other half is the point.
	User string `json:"user"`
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, authStatus{Required: !s.auth.Disabled(), User: s.cfg.AdminUser})
}

// loginRequest is what the login screen posts.
type loginRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

// loginResponse carries the JWT and when it dies, so the dashboard can return to
// the login screen on its own rather than waiting to be told by a 401.
type loginResponse struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
	User    string `json:"user"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCredentialBody)).Decode(&req); err != nil {
		http.Error(w, `body must be {"user": "...", "password": "..."}`, http.StatusBadRequest)
		return
	}

	token, expires, err := s.auth.Login(req.User, req.Password, loginKey(r))
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	case err != nil:
		// Identical for a wrong username and a wrong password, on purpose.
		writeUnauthorized(w, err)
		return
	}
	writeJSON(w, loginResponse{Token: token, Expires: expires.Unix(), User: req.User})
}

// loginKey is what the rate limiter counts against.
//
// RemoteAddr only. X-Forwarded-For is trivially spoofable unless the hop in front
// is known and trusted, and trusting it by default would hand an attacker an
// unlimited supply of distinct keys. Behind a reverse proxy this makes the limit
// global rather than per-client, which is the safe direction to be wrong in.
func loginKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ticketResponse is a short-lived credential for the SSE stream.
type ticketResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresIn int    `json:"expires_in"`
}

func (s *Server) handleTicket(w http.ResponseWriter, r *http.Request) {
	// Verified again inside Ticket, which is where the rule that a ticket cannot
	// mint another ticket lives. The route's own guard would let a token through.
	ticket, ttl, err := s.auth.Ticket(bearerToken(r))
	if err != nil {
		writeUnauthorized(w, err)
		return
	}
	writeJSON(w, ticketResponse{Ticket: ticket, ExpiresIn: int(ttl.Seconds())})
}

// mintRequest asks for a new token.
type mintRequest struct {
	Name  string     `json:"name"`
	Scope auth.Scope `json:"scope"`
}

// mintResponse is the only place a token's secret ever appears.
type mintResponse struct {
	auth.TokenInfo
	// Secret is shown exactly once. Only its digest is stored, so it cannot be
	// recovered — a lost secret means minting another.
	Secret string `json:"secret"`
}

func (s *Server) handleTokens(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.auth.List())
}

func (s *Server) handleMintToken(w http.ResponseWriter, r *http.Request) {
	var req mintRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCredentialBody)).Decode(&req); err != nil {
		http.Error(w, `body must be {"name": "...", "scope": "proxy"|"admin"}`, http.StatusBadRequest)
		return
	}
	secret, info, err := s.auth.Mint(req.Name, req.Scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, mintResponse{TokenInfo: info, Secret: secret})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	switch err := s.auth.Revoke(r.PathValue("id")); {
	case errors.Is(err, auth.ErrNoSuchToken):
		http.Error(w, "no such token", http.StatusNotFound)
	case errors.Is(err, auth.ErrEnvToken):
		http.Error(w, "this token comes from PROXY_TOKEN; change it there and restart",
			http.StatusConflict)
	case err != nil:
		// The token has already stopped working — only saving that fact failed.
		// Say exactly that, rather than implying the revoke did not happen.
		s.log.Error("persist token revocation", "error", err)
		http.Error(w, "revoked, but the change could not be saved and will not survive a restart",
			http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
