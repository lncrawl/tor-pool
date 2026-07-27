package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// newClientServer returns a connected pair for driving the handshake code.
//
// net.Pipe is synchronous and unbuffered: every write blocks until the other
// side reads it. Tests must therefore consume each server reply, and the
// deadline turns a mistake there into a failure instead of a hang.
func newClientServer(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = c.SetDeadline(deadline)
	_ = s.SetDeadline(deadline)
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})
	return c, s
}

// drain reads and discards n bytes, so a server reply cannot block the pipe.
func drain(w io.Reader, n int) {
	_, _ = io.ReadFull(w, make([]byte, n))
}

func TestNegotiateAuthPrefersUserPass(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		// Offer both; the server must choose user/pass to learn the session key.
		_, _ = client.Write([]byte{socks5Version, 2, authNone, authUserPass})
		drain(client, 2) // method selection
		_, _ = client.Write([]byte{userPassVersion, 6})
		_, _ = client.Write([]byte("sess-a"))
		_, _ = client.Write([]byte{1, 'x'})
		drain(client, 2) // auth status
	}()

	key, err := negotiateAuth(server)
	if err != nil {
		t.Fatalf("negotiateAuth: %v", err)
	}
	if key != "sess-a" {
		t.Errorf("session key = %q, want sess-a", key)
	}
}

func TestNegotiateAuthAcceptsEmptyPassword(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, 1, authUserPass})
		drain(client, 2)
		_, _ = client.Write([]byte{userPassVersion, 4})
		_, _ = client.Write([]byte("only"))
		_, _ = client.Write([]byte{0}) // zero-length password
		drain(client, 2)
	}()

	key, err := negotiateAuth(server)
	if err != nil {
		t.Fatalf("negotiateAuth: %v", err)
	}
	if key != "only" {
		t.Errorf("session key = %q, want only", key)
	}
}

func TestNegotiateAuthFallsBackToNone(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, 1, authNone})
		drain(client, 2)
	}()

	key, err := negotiateAuth(server)
	if err != nil {
		t.Fatalf("negotiateAuth: %v", err)
	}
	if key != "" {
		t.Errorf("session key = %q, want empty so the caller applies DEFAULT_SESSION", key)
	}
}

func TestNegotiateAuthRejectsUnknownMethods(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, 1, 0x80}) // unsupported method
		drain(client, 2)
	}()

	if _, err := negotiateAuth(server); err == nil {
		t.Fatal("expected an error when no acceptable method is offered")
	}
}

func TestNegotiateAuthRejectsWrongVersion(t *testing.T) {
	client, server := newClientServer(t)

	go func() { _, _ = client.Write([]byte{0x04, 1, authNone}) }()

	if _, err := negotiateAuth(server); err == nil {
		t.Fatal("expected an error for SOCKS4")
	}
}

func TestNegotiateAuthRejectsZeroMethods(t *testing.T) {
	client, server := newClientServer(t)

	go func() { _, _ = client.Write([]byte{socks5Version, 0}) }()

	if _, err := negotiateAuth(server); err == nil {
		t.Fatal("expected an error when the client offers no methods")
	}
}

func TestReadConnectRequestDomainStaysUnresolved(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		host := "example.com"
		req := []byte{socks5Version, cmdConnect, 0x00, atypDomain, byte(len(host))}
		req = append(req, host...)
		req = append(req, 0x01, 0xbb) // port 443
		_, _ = client.Write(req)
	}()

	tgt, err := readConnectRequest(server)
	if err != nil {
		t.Fatalf("readConnectRequest: %v", err)
	}
	// A domain must survive as a domain, or DNS resolution leaks to the host
	// instead of happening inside Tor.
	if tgt.host != "example.com" || tgt.atyp != atypDomain {
		t.Errorf("target = %+v, want example.com as a domain", tgt)
	}
	if tgt.port != 443 {
		t.Errorf("port = %d, want 443", tgt.port)
	}
}

func TestReadConnectRequestIPv4(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, cmdConnect, 0x00, atypIPv4, 93, 184, 216, 34, 0x00, 0x50})
	}()

	tgt, err := readConnectRequest(server)
	if err != nil {
		t.Fatalf("readConnectRequest: %v", err)
	}
	if tgt.host != "93.184.216.34" || tgt.port != 80 {
		t.Errorf("target = %+v, want 93.184.216.34:80", tgt)
	}
}

func TestReadConnectRequestRejectsBindAndUDP(t *testing.T) {
	for name, cmd := range map[string]byte{"bind": 0x02, "udp associate": 0x03} {
		t.Run(name, func(t *testing.T) {
			client, server := newClientServer(t)

			go func() {
				// Only the 4-byte header: the command is rejected before the
				// address is read, so writing more would block the pipe and
				// stop this goroutine from draining the reply.
				_, _ = client.Write([]byte{socks5Version, cmd, 0x00, atypIPv4})
				drain(client, 10) // the rejection reply
			}()

			if _, err := readConnectRequest(server); err == nil {
				t.Errorf("%s should be rejected: it cannot be carried over tor's SOCKS port", name)
			}
		})
	}
}

func TestReadConnectRequestRejectsEmptyDomain(t *testing.T) {
	client, server := newClientServer(t)

	go func() { _, _ = client.Write([]byte{socks5Version, cmdConnect, 0x00, atypDomain, 0x00}) }()

	if _, err := readConnectRequest(server); err == nil {
		t.Fatal("expected an error for a zero-length domain")
	}
}

func TestReadConnectRequestRejectsUnknownAddressType(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, cmdConnect, 0x00, 0x09})
		drain(client, 10)
	}()

	if _, err := readConnectRequest(server); err == nil {
		t.Fatal("expected an error for an unknown address type")
	}
}

func TestEncodeConnectRequestPreservesDomain(t *testing.T) {
	got, err := encodeConnectRequest(target{host: "example.com", port: 443, atyp: atypDomain})
	if err != nil {
		t.Fatalf("encodeConnectRequest: %v", err)
	}
	want := []byte{socks5Version, cmdConnect, 0x00, atypDomain, 11}
	want = append(want, "example.com"...)
	want = append(want, 0x01, 0xbb)
	if !bytes.Equal(got, want) {
		t.Errorf("encoded = %v\nwant     %v", got, want)
	}
}

func TestEncodeConnectRequestIPv6(t *testing.T) {
	got, err := encodeConnectRequest(target{host: "2001:db8::1", port: 80, atyp: atypIPv6})
	if err != nil {
		t.Fatalf("encodeConnectRequest: %v", err)
	}
	if got[3] != atypIPv6 {
		t.Errorf("address type = %#x, want IPv6", got[3])
	}
	if len(got) != 4+net.IPv6len+2 {
		t.Errorf("length = %d, want %d", len(got), 4+net.IPv6len+2)
	}
}

func TestEncodeConnectRequestRejectsOverlongDomain(t *testing.T) {
	long := bytes.Repeat([]byte("a"), 300)
	if _, err := encodeConnectRequest(target{host: string(long), port: 80, atyp: atypDomain}); err == nil {
		t.Fatal("expected an error: the wire format caps a domain at 255 bytes")
	}
}

func TestReadConnectReplySuccessDrainsBoundAddress(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		// Success, IPv4 bound address, then a byte of tunnelled payload.
		_, _ = server.Write([]byte{socks5Version, replySuccess, 0x00, atypIPv4, 1, 2, 3, 4, 0x1f, 0x90})
		_, _ = server.Write([]byte{'H'})
	}()

	if err := readConnectReply(client); err != nil {
		t.Fatalf("readConnectReply: %v", err)
	}

	// The stream must now sit exactly at the start of the payload; a bound
	// address left undrained would desynchronise everything after it.
	buf := make([]byte, 1)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("reading payload: %v", err)
	}
	if buf[0] != 'H' {
		t.Errorf("payload = %q, want 'H' — bound address was not drained correctly", buf[0])
	}
}

func TestReadConnectReplyFailureIsTypedAndDrains(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = server.Write([]byte{socks5Version, 0x04, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	}()

	err := readConnectReply(client)
	if err == nil {
		t.Fatal("expected an error for a host-unreachable reply")
	}

	// The error must be typed: an upstream refusal is scored against the
	// instance, unlike a client-side protocol error.
	var upstreamErr *UpstreamError
	if !errors.As(err, &upstreamErr) {
		t.Fatalf("error is %T, want *UpstreamError", err)
	}
	if upstreamErr.Code != 0x04 {
		t.Errorf("Code = %#x, want 0x04", upstreamErr.Code)
	}
	if !strings.Contains(upstreamErr.Error(), "host unreachable") {
		t.Errorf("error text should name the condition, got %q", upstreamErr.Error())
	}
}

func TestReadConnectReplyDomainBoundAddress(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		host := "relay.local"
		reply := []byte{socks5Version, replySuccess, 0x00, atypDomain, byte(len(host))}
		reply = append(reply, host...)
		reply = append(reply, 0, 80, 'X')
		_, _ = server.Write(reply)
	}()

	if err := readConnectReply(client); err != nil {
		t.Fatalf("readConnectReply: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(client, buf); err != nil || buf[0] != 'X' {
		t.Errorf("variable-length bound address not drained correctly (read %q, err %v)", buf, err)
	}
}
