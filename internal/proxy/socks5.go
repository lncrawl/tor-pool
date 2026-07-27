// Package proxy implements the client-facing SOCKS5 and HTTP proxy listeners
// and the byte relay between a client and its assigned tor instance.
package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 wire constants. Named rather than inlined because the reply codes in
// particular are easy to transpose.
const (
	socks5Version = 0x05

	authNone         = 0x00
	authUserPass     = 0x02
	authNoAcceptable = 0xff

	userPassVersion = 0x01
	userPassSuccess = 0x00

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	replySuccess             = 0x00
	replyGeneralFailure      = 0x01
	replyHostUnreachable     = 0x04
	replyCommandNotSupported = 0x07
	replyAddrNotSupported    = 0x08
)

const (
	// maxSessionKeyLen is the SOCKS5 protocol's own ceiling: the username
	// length is a single byte, so a key can never exceed 255 bytes. Session
	// keys are untrusted input and this is the only bound the wire format gives
	// us.
	maxSessionKeyLen = 255

	// maxDomainLen is the same single-byte limit applied to a destination
	// hostname. Same number, unrelated concept.
	maxDomainLen = 255
)

// target is a destination as the client asked for it.
//
// A domain is kept as a domain and never resolved locally: resolution has to
// happen inside Tor, or every request leaks its destination to the host's DNS.
// This is what socks5h:// means on the client side.
type target struct {
	host string // domain or IP literal
	port int
	atyp byte
}

func (t target) String() string { return net.JoinHostPort(t.host, strconv.Itoa(t.port)) }

// socksRequest is a parsed client CONNECT, plus whatever credentials arrived
// during negotiation.
type socksRequest struct {
	target     target
	sessionKey string // empty when the client authenticated with "none"
}

// readSocksRequest performs the server side of a SOCKS5 negotiation up to and
// including the CONNECT request, without yet dialling upstream.
//
// The reply to the client is deliberately deferred: it has to report whether
// the *upstream* connection succeeded, which is not known until an instance has
// been picked and dialled.
func readSocksRequest(conn net.Conn) (socksRequest, error) {
	var req socksRequest

	key, err := negotiateAuth(conn)
	if err != nil {
		return req, err
	}
	req.sessionKey = key

	tgt, err := readConnectRequest(conn)
	if err != nil {
		return req, err
	}
	req.target = tgt
	return req, nil
}

// negotiateAuth runs method selection and, if the client offers it,
// username/password authentication.
//
// User/pass is preferred whenever offered, because the username *is* the
// session key — it is how a caller says "keep me on the same instance". The
// password is ignored: this is an identity hint from a caller that already had
// to reach the port, not an access control mechanism.
func negotiateAuth(conn net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read greeting: %w", err)
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("unsupported socks version %d", header[0])
	}

	nMethods := int(header[1])
	if nMethods == 0 {
		return "", errors.New("client offered no auth methods")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read auth methods: %w", err)
	}

	var offersUserPass, offersNone bool
	for _, m := range methods {
		switch m {
		case authUserPass:
			offersUserPass = true
		case authNone:
			offersNone = true
		}
	}

	switch {
	case offersUserPass:
		if _, err := conn.Write([]byte{socks5Version, authUserPass}); err != nil {
			return "", fmt.Errorf("write method selection: %w", err)
		}
		return readUserPass(conn)
	case offersNone:
		if _, err := conn.Write([]byte{socks5Version, authNone}); err != nil {
			return "", fmt.Errorf("write method selection: %w", err)
		}
		return "", nil
	default:
		_, _ = conn.Write([]byte{socks5Version, authNoAcceptable})
		return "", errors.New("no acceptable auth method offered")
	}
}

// readUserPass reads an RFC 1929 username/password sub-negotiation and returns
// the username as the session key.
func readUserPass(conn net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read auth header: %w", err)
	}
	if header[0] != userPassVersion {
		return "", fmt.Errorf("unsupported auth subnegotiation version %d", header[0])
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return "", fmt.Errorf("read username: %w", err)
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return "", fmt.Errorf("read password length: %w", err)
	}
	if n := int(plen[0]); n > 0 {
		// The password is read to keep the stream in sync, then discarded.
		if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
	}

	// Authentication always succeeds; the username is an identity hint.
	if _, err := conn.Write([]byte{userPassVersion, userPassSuccess}); err != nil {
		return "", fmt.Errorf("write auth reply: %w", err)
	}
	return string(username), nil
}

// readConnectRequest reads the SOCKS5 request and rejects anything that is not
// a plain CONNECT.
func readConnectRequest(conn net.Conn) (target, error) {
	var t target

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return t, fmt.Errorf("read request: %w", err)
	}
	if header[0] != socks5Version {
		return t, fmt.Errorf("unsupported socks version %d", header[0])
	}
	if header[1] != cmdConnect {
		// BIND and UDP ASSOCIATE cannot be carried over Tor's SOCKS port.
		writeSocksReply(conn, replyCommandNotSupported)
		return t, fmt.Errorf("unsupported command %#x", header[1])
	}

	t.atyp = header[3]
	switch t.atyp {
	case atypIPv4:
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return t, fmt.Errorf("read ipv4 address: %w", err)
		}
		t.host = net.IP(addr).String()
	case atypIPv6:
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return t, fmt.Errorf("read ipv6 address: %w", err)
		}
		t.host = net.IP(addr).String()
	case atypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return t, fmt.Errorf("read domain length: %w", err)
		}
		if length[0] == 0 {
			return t, errors.New("empty domain name")
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return t, fmt.Errorf("read domain: %w", err)
		}
		t.host = string(name)
	default:
		writeSocksReply(conn, replyAddrNotSupported)
		return t, fmt.Errorf("unsupported address type %#x", t.atyp)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return t, fmt.Errorf("read port: %w", err)
	}
	t.port = int(binary.BigEndian.Uint16(portBytes))
	return t, nil
}

// writeSocksReply sends a reply with an all-zero bound address.
//
// Clients do not use the bound address for CONNECT, and reporting the real one
// would leak an internal instance port to the caller.
func writeSocksReply(conn net.Conn, code byte) {
	// VER, REP, RSV, ATYP=IPv4, 0.0.0.0, port 0
	_, _ = conn.Write([]byte{socks5Version, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}
