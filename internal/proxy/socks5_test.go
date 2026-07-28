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

// testToken is the only credential acceptToken accepts.
const testToken = "tp_ExampleTokenAAAAAAA"

// acceptToken stands in for the real verifier. The handshake depends on nothing
// more than this function, which is why these tests need no credential store.
func acceptToken(secret string) error {
	if secret != testToken {
		return errors.New("unauthorized")
	}
	return nil
}

// collect reads n bytes of server reply in the background and hands them back, so
// a test can assert on the exact bytes instead of merely draining them. net.Pipe
// is synchronous, so the read has to happen while the server is still writing.
func collect(conn io.Reader, n int) <-chan []byte {
	out := make(chan []byte, 1)
	go func() {
		buf := make([]byte, n)
		_, _ = io.ReadFull(conn, buf)
		out <- buf
	}()
	return out
}

func TestNegotiateAuthReadsTheSessionKeyAndChecksThePassword(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		// Offering both is what every real client does; the server must still
		// choose user/pass, because that is where the credential is.
		_, _ = client.Write([]byte{socks5Version, 2, authNone, authUserPass})
		drain(client, 2) // method selection
		_, _ = client.Write([]byte{userPassVersion, 6})
		_, _ = client.Write([]byte("sess-a"))
		_, _ = client.Write([]byte{byte(len(testToken))})
		_, _ = client.Write([]byte(testToken))
		drain(client, 2) // auth status
	}()

	key, err := negotiateAuth(server, acceptToken)
	if err != nil {
		t.Fatalf("negotiateAuth: %v", err)
	}
	if key != "sess-a" {
		t.Errorf("session key = %q, want sess-a", key)
	}
}

// An empty username is still valid: it says "no named session", so the caller
// falls back to DEFAULT_SESSION. The password is what is being checked.
func TestNegotiateAuthAcceptsAnEmptyUsername(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, 1, authUserPass})
		drain(client, 2)
		_, _ = client.Write([]byte{userPassVersion, 0}) // no username
		_, _ = client.Write([]byte{byte(len(testToken))})
		_, _ = client.Write([]byte(testToken))
		drain(client, 2)
	}()

	key, err := negotiateAuth(server, acceptToken)
	if err != nil {
		t.Fatalf("negotiateAuth: %v", err)
	}
	if key != "" {
		t.Errorf("session key = %q, want empty so the caller applies DEFAULT_SESSION", key)
	}
}

func TestNegotiateAuthRefusesAnEmptyPassword(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, 1, authUserPass})
		drain(client, 2)
		_, _ = client.Write([]byte{userPassVersion, 4})
		_, _ = client.Write([]byte("only"))
		_, _ = client.Write([]byte{0}) // zero-length password
		drain(client, 2)
	}()

	if _, err := negotiateAuth(server, acceptToken); err == nil {
		t.Fatal("a zero-length password was accepted")
	}
}

func TestNegotiateAuthRefusesAWrongPassword(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, 1, authUserPass})
		_, _ = client.Write([]byte{userPassVersion, 4})
		_, _ = client.Write([]byte("sess"))
		_, _ = client.Write([]byte{5})
		_, _ = client.Write([]byte("wrong"))
	}()
	// Both replies in one read: a second reader on the pipe would race this one
	// for the method selection.
	got := collect(client, 4)

	if _, err := negotiateAuth(server, acceptToken); err == nil {
		t.Fatal("a wrong password was accepted")
	}

	// RFC 1929's failure reply, and the byte order that matters: the first byte
	// is the sub-negotiation version, not socks5Version. Writing 0x05 here is the
	// classic transposition, and it surfaces to the client as a protocol fault
	// rather than a refused password.
	reply := <-got
	want := []byte{socks5Version, authUserPass, userPassVersion, userPassFailure}
	if !bytes.Equal(reply, want) {
		t.Errorf("reply = %v, want %v", reply, want)
	}
}

// Falling back to "no authentication" would bypass the credential entirely, so a
// client that offers only that is refused.
func TestNegotiateAuthRefusesNoAuthOnly(t *testing.T) {
	client, server := newClientServer(t)

	go func() { _, _ = client.Write([]byte{socks5Version, 1, authNone}) }()
	got := collect(client, 2)

	if _, err := negotiateAuth(server, acceptToken); err == nil {
		t.Fatal("a client offering only 'no authentication' was accepted")
	}
	// 0xFF is RFC 1928's "no acceptable method", after which the client closes.
	want := []byte{socks5Version, authNoAcceptable}
	if reply := <-got; !bytes.Equal(reply, want) {
		t.Errorf("reply = %v, want %v", reply, want)
	}
}

func TestNegotiateAuthRejectsUnknownMethods(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, 1, 0x80}) // unsupported method
		drain(client, 2)
	}()

	if _, err := negotiateAuth(server, acceptToken); err == nil {
		t.Fatal("expected an error when no acceptable method is offered")
	}
}

func TestNegotiateAuthRejectsWrongVersion(t *testing.T) {
	client, server := newClientServer(t)

	go func() { _, _ = client.Write([]byte{0x04, 1, authNone}) }()

	if _, err := negotiateAuth(server, acceptToken); err == nil {
		t.Fatal("expected an error for SOCKS4")
	}
}

func TestNegotiateAuthRejectsZeroMethods(t *testing.T) {
	client, server := newClientServer(t)

	go func() { _, _ = client.Write([]byte{socks5Version, 0}) }()

	if _, err := negotiateAuth(server, acceptToken); err == nil {
		t.Fatal("expected an error when the client offers no methods")
	}
}

// A refused credential must not be answered with the 10-byte connect reply: it
// belongs to a request that has not been read, and sending one desynchronises the
// client. Only the 2-byte auth status goes out.
func TestNegotiateAuthSendsNoConnectReplyOnRefusal(t *testing.T) {
	client, server := newClientServer(t)

	go func() {
		_, _ = client.Write([]byte{socks5Version, 1, authUserPass})
		_, _ = client.Write([]byte{userPassVersion, 1})
		_, _ = client.Write([]byte("s"))
		_, _ = client.Write([]byte{3})
		_, _ = client.Write([]byte("bad"))
	}()
	// Method selection plus the auth status: everything the server should send.
	got := collect(client, 4)

	if _, err := negotiateAuth(server, acceptToken); err == nil {
		t.Fatal("a wrong password was accepted")
	}
	<-got

	// Nothing more may follow. A short read deadline distinguishes "no further
	// bytes" from "the test is hanging".
	_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _ := client.Read(make([]byte, 16)); n != 0 {
		t.Errorf("server sent %d extra bytes after the auth failure", n)
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
