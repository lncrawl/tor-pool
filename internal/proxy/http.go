package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// httpIdleTimeout is how long a client connection may sit between requests
// before it is closed. Without it every keep-alive client that walks away holds
// a goroutine and an upstream tor connection open indefinitely.
const httpIdleTimeout = 2 * time.Minute

// hopByHopHeaders never reach the origin server. Proxy-Authorization carries the
// session key and forwarding it would hand every visited site the key that names
// this caller's exit identity.
var hopByHopHeaders = []string{
	"Proxy-Authorization",
	"Proxy-Connection",
	"Connection",
	"Keep-Alive",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// handleHTTP serves one client on the HTTP proxy port, handling both CONNECT
// tunnels and plain absolute-URI requests.
//
// This is hand-rolled rather than built on net/http because a proxy has to own
// the raw connection for CONNECT, and because a session must map to exactly one
// upstream instance for the life of a tunnel.
//
// Plain requests are served in a loop, each routed on its own. A keep-alive
// client sends requests for several hosts down one connection, so a proxy that
// dials once and then relays raw bytes delivers the second request to the first
// request's host. Routing per request also means a rotation takes effect on the
// very next plain request rather than whenever the client happens to reconnect.
func (s *Server) handleHTTP(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	br := bufio.NewReader(client)
	var upstream *httpUpstream
	defer func() {
		if upstream != nil {
			upstream.close()
		}
	}()

	for {
		if err := client.SetReadDeadline(time.Now().Add(httpIdleTimeout)); err != nil {
			return
		}
		req, err := http.ReadRequest(br)
		if err != nil {
			// EOF or an idle timeout is how a keep-alive connection ends.
			s.log.Debug("http proxy read finished", "remote", remoteHost(client), "error", err)
			return
		}
		if err := client.SetReadDeadline(time.Time{}); err != nil {
			return
		}

		key := s.sessionKey(proxyAuthSession(req), client)
		tgt, err := httpTarget(req)
		if err != nil {
			// A request with no absolute URI is a browser talking to us as if we
			// were an origin server, not a proxy. Nothing was routed, so nothing
			// is scored.
			writeHTTPError(client, http.StatusBadRequest, err.Error())
			return
		}

		instance, socksAddr, err := s.router.RouteAddr(key)
		if err != nil {
			s.log.Warn("no instance for session", "session", key, "error", err)
			writeHTTPError(client, http.StatusServiceUnavailable, "no healthy tor instance available")
			return
		}

		if req.Method == http.MethodConnect {
			// A tunnel owns the rest of the connection: once it is established
			// there are no more proxy-level requests to read.
			s.tunnel(ctx, client, br, key, instance, socksAddr, tgt)
			return
		}

		// One upstream per (instance, target) so a keep-alive client talking to
		// one host reuses its connection, and one talking to several does not
		// have its requests crossed.
		if upstream != nil && !upstream.serves(instance, tgt) {
			upstream.close()
			upstream = nil
		}
		if upstream == nil {
			upstream, err = s.dialUpstream(ctx, key, instance, socksAddr, tgt)
			if err != nil {
				writeHTTPError(client, http.StatusBadGateway, "tor could not reach the destination")
				return
			}
			s.sampleExitSoon(ctx, instance)
		}

		keepClient, keepUpstream := s.exchange(client, upstream, req, key)
		if !keepUpstream {
			upstream.close()
			upstream = nil
		}
		if !keepClient {
			return
		}
	}
}

// httpUpstream is one connection to an origin server through a tor instance.
type httpUpstream struct {
	conn     net.Conn
	reader   *bufio.Reader
	instance int
	target   string
	latency  time.Duration
}

func (u *httpUpstream) serves(instance int, t target) bool {
	return u.instance == instance && u.target == t.String()
}

func (u *httpUpstream) close() { _ = u.conn.Close() }

// dialUpstream opens a connection to the target through an instance, scoring the
// instance if it cannot.
func (s *Server) dialUpstream(
	ctx context.Context, key string, instance int, socksAddr string, t target,
) (*httpUpstream, error) {
	start := time.Now()
	conn, err := dialThroughInstance(ctx, socksAddr, t)
	if err != nil {
		s.reportDialFailure(instance, key, t, err)
		return nil, err
	}
	return &httpUpstream{
		conn:     conn,
		reader:   bufio.NewReader(conn),
		instance: instance,
		target:   t.String(),
		latency:  time.Since(start),
	}, nil
}

// exchange forwards one request and copies the response back, reporting which of
// the two connections can carry another.
//
// They are separate answers: an origin server that closes after responding says
// nothing about whether this client can send another request, and closing the
// client connection for it would make every such response look to the client
// like the proxy hung up.
func (s *Server) exchange(
	client net.Conn, up *httpUpstream, req *http.Request, key string,
) (keepClient, keepUpstream bool) {
	clientWantsClose := req.Close || strings.EqualFold(req.Header.Get("Connection"), "close")

	if err := forwardRequest(up.conn, req); err != nil {
		s.log.Debug("forwarding request failed", "session", key, "error", err)
		s.router.RecordTransportFailure(up.instance, "request_write_error")
		s.router.Finish(key, Outcome{Instance: up.instance, Failed: true})
		return false, false
	}

	resp, err := http.ReadResponse(up.reader, req)
	if err != nil {
		s.log.Debug("reading upstream response failed", "session", key, "error", err)
		s.router.RecordTransportFailure(up.instance, "response_read_error")
		s.router.Finish(key, Outcome{Instance: up.instance, Failed: true})
		writeHTTPError(client, http.StatusBadGateway, "no response from the destination")
		return false, false
	}

	// resp.Write reads the body to EOF, which is also what leaves the upstream
	// connection positioned for the next response.
	counter := &countingWriter{w: client}
	writeErr := resp.Write(counter)
	_ = resp.Body.Close()

	s.router.Finish(key, Outcome{
		Instance:  up.instance,
		BytesUp:   requestSize(req),
		BytesDown: counter.n,
		Latency:   up.latency,
		Failed:    writeErr != nil,
	})
	if writeErr != nil {
		s.log.Debug("writing response to client failed", "session", key, "error", writeErr)
		return false, false
	}
	// Only the first request through a connection paid for the handshake.
	up.latency = 0
	return !clientWantsClose, !resp.Close
}

// tunnel establishes a CONNECT tunnel and relays it until either side closes.
func (s *Server) tunnel(
	ctx context.Context, client net.Conn, br *bufio.Reader,
	key string, instance int, socksAddr string, t target,
) {
	dialStart := time.Now()
	upstream, err := dialThroughInstance(ctx, socksAddr, t)
	if err != nil {
		s.reportDialFailure(instance, key, t, err)
		writeHTTPError(client, http.StatusBadGateway, "tor could not reach the destination")
		return
	}
	latency := time.Since(dialStart)
	defer func() { _ = upstream.Close() }()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		// The client is gone. It never got a tunnel, so this is not the
		// instance's failure — but the request must still be closed out, or the
		// session keeps an in-flight request forever and is never swept.
		s.router.Finish(key, Outcome{Instance: instance, Latency: latency})
		return
	}

	s.sampleExitSoon(ctx, instance)

	// Anything the client pipelined behind the CONNECT — a TLS ClientHello,
	// typically — is already in the reader and must be relayed, not dropped.
	if buffered := br.Buffered(); buffered > 0 {
		pending, err := br.Peek(buffered)
		if err == nil {
			if _, err := upstream.Write(pending); err != nil {
				s.log.Debug("flushing buffered client bytes failed", "session", key, "error", err)
			}
			_, _ = br.Discard(buffered)
		}
	}

	s.finish(key, instance, t, latency, relay(client, upstream))
}

// countingWriter counts what it passes through, so a response written with
// resp.Write can still be accounted for.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// requestSize approximates the bytes a request cost upstream. Only the body is
// known exactly; a negative ContentLength means chunked, which is rare enough
// for a proxy's own byte counters not to warrant buffering it to find out.
func requestSize(req *http.Request) int64 {
	if req.ContentLength > 0 {
		return req.ContentLength
	}
	return 0
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
		// No port. An IPv6 literal still arrives bracketed, and those brackets
		// are part of the URL syntax, not of the address — left on, the address
		// parses as neither an IP nor a resolvable name, so tor was asked to look
		// up the literal string "[::1]".
		hostname, portStr = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), defaultPort
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
// origin form, with hop-by-hop headers stripped.
func forwardRequest(upstream net.Conn, req *http.Request) error {
	for _, header := range hopByHopHeaders {
		req.Header.Del(header)
	}
	// Let Request.Write decide the framing from the body it has, rather than
	// forwarding the client's own idea of it.
	req.Close = false

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
