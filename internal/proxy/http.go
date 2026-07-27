package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleHTTP serves one client on the HTTP proxy port, handling both CONNECT
// tunnels and plain absolute-URI requests.
//
// This is hand-rolled rather than built on net/http because a proxy has to own
// the raw connection for CONNECT, and because a session must map to exactly one
// upstream instance for the life of the connection.
func (s *Server) handleHTTP(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		s.log.Debug("http proxy read failed", "remote", remoteHost(client), "error", err)
		return
	}

	key := s.sessionKey(proxyAuthSession(req), client)
	instance, socksAddr, err := s.router.RouteAddr(key)
	if err != nil {
		s.log.Warn("no instance for session", "session", key, "error", err)
		writeHTTPError(client, http.StatusServiceUnavailable, "no healthy tor instance available")
		return
	}

	tgt, err := httpTarget(req)
	if err != nil {
		// A request with no absolute URI is a browser talking to us as if we
		// were an origin server, not a proxy.
		writeHTTPError(client, http.StatusBadRequest, err.Error())
		return
	}

	dialStart := time.Now()
	upstream, err := dialThroughInstance(ctx, socksAddr, tgt)
	if err != nil {
		s.reportDialFailure(instance, key, tgt, err)
		writeHTTPError(client, http.StatusBadGateway, "tor could not reach the destination")
		return
	}
	latency := time.Since(dialStart)
	defer func() { _ = upstream.Close() }()

	if req.Method == http.MethodConnect {
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
	} else if err := forwardRequest(upstream, req); err != nil {
		s.log.Debug("forwarding request failed", "session", key, "error", err)
		s.router.RecordTransportFailure(instance, "request_write_error")
		s.router.Finish(key, Outcome{Instance: instance, Failed: true})
		return
	}

	s.sampleExitSoon(ctx, instance)

	// Anything the client pipelined behind the request header is already in the
	// reader and must be relayed, not dropped.
	if buffered := br.Buffered(); buffered > 0 {
		pending, err := br.Peek(buffered)
		if err == nil {
			if _, err := upstream.Write(pending); err != nil {
				s.log.Debug("flushing buffered client bytes failed", "session", key, "error", err)
			}
			_, _ = br.Discard(buffered)
		}
	}

	s.finish(key, instance, tgt, latency, relay(client, upstream))
}

// httpTarget derives the destination from a proxy request.
func httpTarget(req *http.Request) (target, error) {
	host := req.Host
	if req.Method != http.MethodConnect && req.URL != nil && req.URL.Host != "" {
		host = req.URL.Host
	}
	if host == "" {
		return target{}, fmt.Errorf("%s request has no absolute URI or Host header", req.Method)
	}

	defaultPort := "80"
	if req.Method == http.MethodConnect {
		// CONNECT authority form is host:port, but tolerate a bare host.
		defaultPort = "443"
	} else if req.URL != nil && req.URL.Scheme == "https" {
		defaultPort = "443"
	}

	hostname, portStr, err := net.SplitHostPort(host)
	if err != nil {
		hostname, portStr = host, defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return target{}, fmt.Errorf("invalid port %q", portStr)
	}

	t := target{host: hostname, port: port, atyp: atypDomain}
	// Preserve a literal IP as a literal, but keep hostnames as names so DNS
	// resolution happens inside Tor.
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.To4() != nil {
			t.atyp = atypIPv4
		} else {
			t.atyp = atypIPv6
		}
	}
	return t, nil
}

// forwardRequest writes a non-CONNECT request to the upstream connection in
// origin form, with proxy-only headers stripped.
func forwardRequest(upstream net.Conn, req *http.Request) error {
	// Proxy-Authorization carries the session key and is meaningless to the
	// origin server; forwarding it would leak the key to every site visited.
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	if err := req.Write(upstream); err != nil {
		return fmt.Errorf("write request upstream: %w", err)
	}
	return nil
}

// proxyAuthSession extracts a session key from Proxy-Authorization.
//
// The password is ignored, exactly as with SOCKS credentials: the username is an
// identity hint, not an access control mechanism.
func proxyAuthSession(req *http.Request) string {
	header := req.Header.Get("Proxy-Authorization")
	encoded, ok := strings.CutPrefix(header, "Basic ")
	if !ok {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return ""
	}
	user, _, _ := strings.Cut(string(decoded), ":")
	return user
}

func writeHTTPError(conn net.Conn, status int, message string) {
	body := message + "\n"
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}
