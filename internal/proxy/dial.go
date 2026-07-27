package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// upstreamTimeout bounds a single SOCKS handshake with a tor instance. Building
// a circuit to a new destination can be slow, but not minutes-slow; a stuck
// handshake must surface as a transport failure so the instance gets scored.
const upstreamTimeout = 60 * time.Second

// dialThroughInstance opens a connection to target via a tor instance's SOCKS
// port.
//
// No credentials are sent upstream on purpose. Tor's IsolateSOCKSAuth is on by
// default, so passing the session key through would give every session its own
// circuit *inside* one instance — two callers pinned to the same instance would
// then see different exit IPs, which contradicts the model this pool is built
// on ("one instance is one exit identity") and would make the reported
// per-instance exit IP meaningless.
func dialThroughInstance(ctx context.Context, socksAddr string, t target) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, fmt.Errorf("dial instance socks %s: %w", socksAddr, err)
	}

	// A deadline covers the whole handshake; it is cleared before the caller
	// takes over, so relaying is not bounded by it.
	deadline := time.Now().Add(upstreamTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}

	if err := clientHandshake(conn, t); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear handshake deadline: %w", err)
	}
	return conn, nil
}

// clientHandshake performs a no-auth SOCKS5 CONNECT against tor.
func clientHandshake(conn net.Conn, t target) error {
	if _, err := conn.Write([]byte{socks5Version, 0x01, authNone}); err != nil {
		return fmt.Errorf("write socks greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read socks method selection: %w", err)
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("instance replied with socks version %d", resp[0])
	}
	if resp[1] != authNone {
		return fmt.Errorf("instance demanded auth method %#x", resp[1])
	}

	req, err := encodeConnectRequest(t)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write socks connect: %w", err)
	}
	return readConnectReply(conn)
}

// encodeConnectRequest builds a CONNECT request, preserving a domain as a
// domain so that DNS resolution happens inside Tor.
func encodeConnectRequest(t target) ([]byte, error) {
	buf := []byte{socks5Version, cmdConnect, 0x00}

	switch t.atyp {
	case atypDomain:
		if len(t.host) > maxDomainLen {
			return nil, fmt.Errorf("domain name too long (%d bytes)", len(t.host))
		}
		buf = append(buf, atypDomain, byte(len(t.host)))
		buf = append(buf, t.host...)
	default:
		ip := net.ParseIP(t.host)
		if ip == nil {
			// An address type of IPv4/IPv6 with an unparseable host means the
			// request was malformed upstream of here.
			return nil, fmt.Errorf("invalid IP address %q", t.host)
		}
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, atypIPv4)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, atypIPv6)
			buf = append(buf, ip.To16()...)
		}
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(t.port)) //nolint:gosec // range-checked by the wire format
	return append(buf, port...), nil
}

// readConnectReply reads tor's reply and consumes the variable-length bound
// address so the stream is positioned at the start of the tunnelled data.
func readConnectReply(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read socks reply: %w", err)
	}
	if header[0] != socks5Version {
		return fmt.Errorf("instance replied with socks version %d", header[0])
	}

	// The bound address must be drained even on failure, or a reused
	// connection would desynchronise. Length depends on the address type.
	var addrLen int
	switch header[3] {
	case atypIPv4:
		addrLen = net.IPv4len
	case atypIPv6:
		addrLen = net.IPv6len
	case atypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return fmt.Errorf("read bound domain length: %w", err)
		}
		addrLen = int(length[0])
	default:
		return fmt.Errorf("instance replied with address type %#x", header[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addrLen)+2); err != nil {
		return fmt.Errorf("drain bound address: %w", err)
	}

	if header[1] != replySuccess {
		return &UpstreamError{Code: header[1]}
	}
	return nil
}

// UpstreamError is a non-success SOCKS reply from a tor instance. It means the
// instance could not reach the destination — a signal worth scoring against
// that instance, unlike a client-side protocol error.
type UpstreamError struct {
	Code byte
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("tor refused the connection (socks reply %#x: %s)", e.Code, socksReplyText(e.Code))
}

func socksReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "ttl expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown"
	}
}
