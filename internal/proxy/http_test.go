package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lncrawl/tor-pool/internal/config"
)

// fakeRouter stands in for the pool: one instance, one address, and a record of
// what was finished so the accounting can be asserted.
type fakeRouter struct {
	addr string

	mu       sync.Mutex
	routes   int
	keys     []string
	finished []Outcome
	failures []string
}

func (r *fakeRouter) RouteAddr(key string) (int, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes++
	r.keys = append(r.keys, key)
	return 0, r.addr, nil
}

// sessionKeys is what each request was routed under, which is how a test proves
// a caller kept its stickiness.
func (r *fakeRouter) sessionKeys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.keys...)
}

func (r *fakeRouter) Finish(_ string, out Outcome) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished = append(r.finished, out)
}

func (r *fakeRouter) RecordTransportFailure(_ int, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, reason)
}

func (r *fakeRouter) SampleExit(int) {}

func (r *fakeRouter) counts() (routes, finished, failures int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.routes, len(r.finished), len(r.failures)
}

// fakeTor is a SOCKS5 listener that answers CONNECT and then behaves as the
// origin server for whatever host it was asked for, naming that host in every
// response body. A response that names the wrong host is a misrouted request.
func fakeTor(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeTor(conn)
		}
	}()
	return ln.Addr().String()
}

func serveFakeTor(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, int(greeting[1]))); err != nil {
		return
	}
	if _, err := conn.Write([]byte{socks5Version, authNone}); err != nil {
		return
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	length := make([]byte, 1)
	if _, err := io.ReadFull(conn, length); err != nil {
		return
	}
	host := make([]byte, int(length[0]))
	if _, err := io.ReadFull(conn, host); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		return
	}
	if _, err := conn.Write([]byte{socks5Version, replySuccess, 0, atypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Now the origin server for that host, keeping the connection alive.
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body := fmt.Sprintf("served %s%s", host, req.URL.RequestURI())
		if _, err := fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
			len(body), body); err != nil {
			return
		}
	}
}

func newProxyServer(t *testing.T, router Router) *Server {
	t.Helper()
	cfg := config.Defaults()
	return NewServer(&cfg, router, acceptToken, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// newOpenProxyServer is newProxyServer with AUTH_DISABLED set. The verifier is
// still supplied, exactly as the binary supplies it, so the test covers the
// listener consulting the flag rather than a server built without a verifier.
func newOpenProxyServer(t *testing.T, router Router) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.AuthDisabled = true
	return NewServer(&cfg, router, acceptToken, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// proxyAuth is the Proxy-Authorization header for a session, carrying the
// credential the fake verifier accepts.
func proxyAuth(session string) string {
	return "Proxy-Authorization: Basic " +
		base64.StdEncoding.EncodeToString([]byte(session+":"+testToken)) + "\r\n"
}

func TestHTTPProxyRoutesEachKeepAliveRequest(t *testing.T) {
	// The regression this guards: a keep-alive client sends requests for several
	// hosts down one proxy connection. Dialling once and then relaying raw bytes
	// delivered the second request to the first request's host.
	router := &fakeRouter{addr: fakeTor(t)}
	s := newProxyServer(t, router)

	client, server := newClientServer(t)
	go s.handleHTTP(context.Background(), server)

	send := func(url, host string) {
		fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", url, host, proxyAuth("sess"))
	}
	br := bufio.NewReader(client)
	read := func() string {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	send("http://alpha.example/one", "alpha.example")
	if got := read(); got != "served alpha.example/one" {
		t.Errorf("first response = %q", got)
	}

	send("http://beta.example/two", "beta.example")
	if got := read(); got != "served beta.example/two" {
		t.Errorf("second response = %q, want it served by beta.example", got)
	}

	// Same host again: the upstream connection is reused rather than redialled,
	// but the request is still routed so a rotation takes effect immediately.
	send("http://beta.example/three", "beta.example")
	if got := read(); got != "served beta.example/three" {
		t.Errorf("third response = %q", got)
	}

	// Finish lands just after the response is on the wire, so the last one can
	// still be in flight when the client has already read it.
	routes, finished, failures := router.counts()
	for range 100 {
		if finished == 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
		routes, finished, failures = router.counts()
	}

	if routes != 3 {
		t.Errorf("routed %d times, want one per request", routes)
	}
	if finished != 3 {
		t.Errorf("finished %d requests, want 3 — a request left open never lets its session expire", finished)
	}
	if failures != 0 {
		t.Errorf("recorded %d transport failures, want none", failures)
	}
}

func TestHTTPProxyRefusesRequestsWithoutACredential(t *testing.T) {
	router := &fakeRouter{addr: fakeTor(t)}
	s := newProxyServer(t, router)

	client, server := newClientServer(t)
	go s.handleHTTP(context.Background(), server)

	fmt.Fprint(client, "GET http://alpha.example/one HTTP/1.1\r\nHost: alpha.example\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	// 407, not 401: this is the proxy refusing, not an origin server.
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want 407", resp.StatusCode)
	}
	// RFC 9110 §15.5.8 makes the challenge a MUST. Without it curl and browsers
	// never re-send credentials and report a protocol violation instead.
	if challenge := resp.Header.Get("Proxy-Authenticate"); !strings.HasPrefix(challenge, "Basic ") {
		t.Errorf("Proxy-Authenticate = %q, want a Basic challenge", challenge)
	}

	// Nothing was routed, so no instance was involved and none may be blamed.
	routes, finished, failures := router.counts()
	if routes != 0 || finished != 0 || failures != 0 {
		t.Errorf("routed %d, finished %d, failures %d — a refused request must touch no instance",
			routes, finished, failures)
	}
}

// With AUTH_DISABLED a request with no Proxy-Authorization must be served rather
// than challenged. A 407 here would be unanswerable: the operator turned auth off
// precisely so there would be no credential to send.
func TestHTTPProxyServesWithoutACredentialWhenDisabled(t *testing.T) {
	router := &fakeRouter{addr: fakeTor(t)}
	s := newOpenProxyServer(t, router)

	client, server := newClientServer(t)
	go s.handleHTTP(context.Background(), server)

	fmt.Fprint(client, "GET http://alpha.example/one HTTP/1.1\r\nHost: alpha.example\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "served alpha.example/one" {
		t.Errorf("body = %q", body)
	}
}

// A caller that keeps sending its old credential must keep its session. The
// password is ignored, but the username beside it is the session key, and losing
// it would move every caller onto one exit IP.
func TestHTTPProxyKeepsTheSessionKeyWhenDisabled(t *testing.T) {
	router := &fakeRouter{addr: fakeTor(t)}
	s := newOpenProxyServer(t, router)

	client, server := newClientServer(t)
	go s.handleHTTP(context.Background(), server)

	// A password the verifier would refuse, to prove it is never consulted.
	header := "Proxy-Authorization: Basic " +
		base64.StdEncoding.EncodeToString([]byte("sess-a:stale-token")) + "\r\n"
	fmt.Fprintf(client, "GET http://alpha.example/one HTTP/1.1\r\nHost: alpha.example\r\n%s\r\n", header)

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if keys := router.sessionKeys(); len(keys) != 1 || keys[0] != "sess-a" {
		t.Errorf("routed under %v, want [sess-a]", keys)
	}
}

func TestHTTPProxyRefusesBadCredentials(t *testing.T) {
	cases := map[string]string{
		"wrong password":  "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("sess:wrong")) + "\r\n",
		"no colon":        "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("sess")) + "\r\n",
		"not base64":      "Proxy-Authorization: Basic !!!!\r\n",
		"wrong scheme":    "Proxy-Authorization: Bearer " + testToken + "\r\n",
		"empty password":  "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("sess:")) + "\r\n",
		"session as pass": "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(testToken+":sess")) + "\r\n",
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			s := newProxyServer(t, &fakeRouter{addr: fakeTor(t)})
			client, server := newClientServer(t)
			go s.handleHTTP(context.Background(), server)

			fmt.Fprintf(client, "GET http://alpha.example/ HTTP/1.1\r\nHost: alpha.example\r\n%s\r\n", header)
			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Errorf("status = %d, want 407", resp.StatusCode)
			}
		})
	}
}

// A keep-alive client can drop the header on its second request. Checking only the
// first would let that one ride on the first request's credential.
func TestHTTPProxyChecksEveryKeepAliveRequest(t *testing.T) {
	s := newProxyServer(t, &fakeRouter{addr: fakeTor(t)})
	client, server := newClientServer(t)
	go s.handleHTTP(context.Background(), server)

	br := bufio.NewReader(client)

	fmt.Fprintf(client, "GET http://alpha.example/one HTTP/1.1\r\nHost: alpha.example\r\n%s\r\n",
		proxyAuth("sess"))
	first, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	_, _ = io.Copy(io.Discard, first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.StatusCode)
	}

	fmt.Fprint(client, "GET http://alpha.example/two HTTP/1.1\r\nHost: alpha.example\r\n\r\n")
	second, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read second response: %v", err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("second status = %d, want 407 — the credential is per request", second.StatusCode)
	}
}

func TestHTTPProxyRefusesCONNECTWithoutACredential(t *testing.T) {
	s := newProxyServer(t, &fakeRouter{addr: fakeTor(t)})
	client, server := newClientServer(t)
	go s.handleHTTP(context.Background(), server)

	// A tunnel with no credential must be refused before it is established, not
	// answered with 200 and then failed.
	fmt.Fprint(client, "CONNECT alpha.example:443 HTTP/1.1\r\nHost: alpha.example:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Error("407 without a Proxy-Authenticate challenge")
	}
}

func TestHTTPProxyStripsHopByHopHeaders(t *testing.T) {
	var sent strings.Builder
	upstream := &recordingConn{sb: &sent}

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET http://example.com/x HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Proxy-Authorization: Basic c2Vzczp4\r\n" +
			"Proxy-Connection: keep-alive\r\n" +
			"Connection: close\r\n" +
			"X-Keep: yes\r\n\r\n")))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}

	if err := forwardRequest(upstream, req); err != nil {
		t.Fatalf("forwardRequest: %v", err)
	}
	wire := sent.String()

	// Proxy-Authorization now carries the credential itself, so forwarding it
	// would hand every visited site a working proxy token — it used to leak only
	// the session name.
	for _, header := range []string{"Proxy-Authorization", "Proxy-Connection", "Connection:"} {
		if strings.Contains(wire, header) {
			t.Errorf("%s reached the origin:\n%s", header, wire)
		}
	}
	if !strings.Contains(wire, "X-Keep: yes") {
		t.Errorf("end-to-end header dropped:\n%s", wire)
	}
	// Origin form, not the absolute URI the client sent us.
	if !strings.HasPrefix(wire, "GET /x HTTP/1.1\r\n") {
		t.Errorf("request line not rewritten to origin form:\n%s", wire)
	}
}

func TestHTTPTargetDefaultsAndLiterals(t *testing.T) {
	cases := map[string]struct {
		method, url, host string
		want              string
		atyp              byte
	}{
		"plain http":     {http.MethodGet, "http://example.com/x", "example.com", "example.com:80", atypDomain},
		"explicit port":  {http.MethodGet, "http://example.com:8080/x", "example.com:8080", "example.com:8080", atypDomain},
		"connect":        {http.MethodConnect, "example.com:443", "example.com:443", "example.com:443", atypDomain},
		"connect bare":   {http.MethodConnect, "example.com", "example.com", "example.com:443", atypDomain},
		"ipv4 literal":   {http.MethodGet, "http://1.2.3.4/x", "1.2.3.4", "1.2.3.4:80", atypIPv4},
		"ipv6 literal":   {http.MethodGet, "http://[::1]/x", "[::1]", "[::1]:80", atypIPv6},
		"https absolute": {http.MethodGet, "https://example.com/x", "example.com", "example.com:443", atypDomain},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", tc.method, tc.url, tc.host)
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
			if err != nil {
				t.Fatalf("read request: %v", err)
			}
			got, err := httpTarget(req)
			if err != nil {
				t.Fatalf("httpTarget: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("target = %q, want %q", got.String(), tc.want)
			}
			if got.atyp != tc.atyp {
				t.Errorf("atyp = %#x, want %#x", got.atyp, tc.atyp)
			}
		})
	}
}

// recordingConn captures what a handler writes upstream.
type recordingConn struct {
	net.Conn
	sb *strings.Builder
}

func (c *recordingConn) Write(b []byte) (int, error) { return c.sb.Write(b) }

// unused, but keeps encoding/binary imported for the SOCKS helper above.
var _ = binary.BigEndian

// A destination tor was never going to reach must not be blamed on the instance.
//
// Found by the SSRF check in the auth work: three requests for 127.0.0.1 refused
// by tor were enough to quarantine a healthy instance under the default
// thresholds, and enough of them empty the pool. The refusal is the caller's
// fault, not the circuit's.
func TestUnroutableTargetsAreNotScored(t *testing.T) {
	unroutable := []string{
		"127.0.0.1", "::1", "10.1.2.3", "192.168.1.1", "172.16.0.1",
		"169.254.1.1", "0.0.0.0", "224.0.0.1", "fd00::1", "fe80::1",
	}
	for _, host := range unroutable {
		if !unroutableTarget(target{host: host, port: 80}) {
			t.Errorf("%s should not be scored against an instance", host)
		}
	}

	// Public literals and hostnames stay the instance's problem: a name that
	// will not resolve really can mean a broken circuit.
	for _, host := range []string{
		"93.184.216.34", "1.1.1.1", "2606:4700::1111", "example.com", "localhost",
	} {
		if unroutableTarget(target{host: host, port: 80}) {
			t.Errorf("%s should still be scored — it is not unroutable by construction", host)
		}
	}
}
