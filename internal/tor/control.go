// Package tor renders per-instance configuration, speaks the control protocol,
// and supervises tor child processes.
package tor

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrNotAuthenticated is returned when a command is issued before Authenticate.
var ErrNotAuthenticated = errors.New("tor: control connection is not authenticated")

// ControlError is a non-2xx reply from the control port. Tor's own status code
// and message are preserved because they are far more specific than anything we
// could infer (e.g. 514 for bad authentication vs 515 for a bad password).
type ControlError struct {
	Code  int
	Reply string
	Cmd   string
}

func (e *ControlError) Error() string {
	return fmt.Sprintf("tor: %s failed: %d %s", e.Cmd, e.Code, e.Reply)
}

// Control is a client for a single tor control port.
//
// It is not safe for concurrent use: the control protocol is a synchronous
// request/reply stream over one connection, so callers must serialise commands.
// The pool holds one Control per instance and guards it with the instance lock.
type Control struct {
	conn net.Conn
	r    *bufio.Reader

	authenticated bool

	// lastNewnym is when this connection last sent an effective NEWNYM. Tor
	// exposes no way to query its own cooldown timer, so tracking it here is
	// the only way to know whether the next signal will actually be honoured.
	// It doubles as the cutoff for which circuits may still be reported as this
	// instance's exit, because NEWNYM makes every older circuit unusable.
	lastNewnym time.Time

	// lastExit is the exit fingerprint ExitNode reported last. Holding onto it
	// keeps an idle instance reporting one identity instead of following tor
	// around its preemptively built circuits.
	lastExit string
}

// Dial opens a control connection. The caller must call Authenticate before
// issuing any other command.
func Dial(ctx context.Context, addr string) (*Control, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial control port %s: %w", addr, err)
	}
	return &Control{conn: conn, r: bufio.NewReader(conn)}, nil
}

// Close releases the connection.
func (c *Control) Close() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	c.authenticated = false
	return err
}

// AuthenticateCookie authenticates with the contents of tor's control auth
// cookie file.
//
// Cookie auth is used instead of a password because the control ports are bound
// to container loopback and never published: there is no password to manage,
// rotate, or leak, and no `tor --hash-password` fork per instance. The cookie is
// sent as hex, which is what tor expects for the raw AUTHENTICATE form.
func (c *Control) AuthenticateCookie(cookiePath string) error {
	cookie, err := os.ReadFile(cookiePath)
	if err != nil {
		return fmt.Errorf("read control cookie: %w", err)
	}
	if _, err := c.command("AUTHENTICATE " + hex.EncodeToString(cookie)); err != nil {
		return err
	}
	c.authenticated = true
	return nil
}

// Signal sends a SIGNAL command, e.g. "NEWNYM".
func (c *Control) Signal(name string) error {
	if !c.authenticated {
		return ErrNotAuthenticated
	}
	if _, err := c.command("SIGNAL " + name); err != nil {
		return err
	}
	if strings.EqualFold(name, "NEWNYM") {
		c.lastNewnym = time.Now()
		// The exit we were reporting is exactly the one this signal retired.
		c.lastExit = ""
	}
	return nil
}

// GetInfo returns the value of a single GETINFO key.
func (c *Control) GetInfo(key string) (string, error) {
	if !c.authenticated {
		return "", ErrNotAuthenticated
	}
	reply, err := c.command("GETINFO " + key)
	if err != nil {
		return "", err
	}
	return parseGetInfo(reply, key)
}

// SetConf applies configuration at runtime, e.g. SetConf("ExitNodes", "{us}").
// An empty value resets the option to its default.
func (c *Control) SetConf(key, value string) error {
	if !c.authenticated {
		return ErrNotAuthenticated
	}
	cmd := "SETCONF " + key
	if value != "" {
		cmd += "=" + quoteControlValue(value)
	}
	_, err := c.command(cmd)
	return err
}

// BootstrapPercent reports how far this instance has bootstrapped, 0..100.
func (c *Control) BootstrapPercent() (int, error) {
	v, err := c.GetInfo("status/bootstrap-phase")
	if err != nil {
		return 0, err
	}
	// The value looks like:
	//   NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"
	for _, field := range strings.Fields(v) {
		suffix, ok := strings.CutPrefix(field, "PROGRESS=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(suffix)
		if err != nil {
			return 0, fmt.Errorf("tor: unparseable bootstrap progress %q", field)
		}
		return n, nil
	}
	return 0, fmt.Errorf("tor: no PROGRESS in bootstrap phase %q", v)
}

// NewnymCooldown is tor's rate limit between NEWNYM signals that actually take
// effect. A signal sent inside the cooldown returns 250 OK and is then silently
// coalesced, which is exactly the failure that makes rotation look broken.
const NewnymCooldown = 10 * time.Second

// NewnymWait reports how long to wait before a NEWNYM on this connection will
// actually build a fresh circuit. Zero means "signal now".
//
// Tor offers no way to ask it how much cooldown is left, so this is measured
// from the last NEWNYM this connection sent. A NEWNYM sent by some other
// controller is invisible to us — the pool keeps one long-lived connection per
// instance precisely so this stays accurate.
func (c *Control) NewnymWait() time.Duration {
	if c.lastNewnym.IsZero() {
		return 0
	}
	if remaining := NewnymCooldown - time.Since(c.lastNewnym); remaining > 0 {
		return remaining
	}
	return 0
}

// Newnym waits out any remaining cooldown, then requests a new circuit. It
// returns early if ctx is cancelled while waiting.
func (c *Control) Newnym(ctx context.Context) error {
	if wait := c.NewnymWait(); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return c.Signal("NEWNYM")
}

// ExitNode describes the exit relay of a circuit.
type ExitNode struct {
	Fingerprint string
	Nickname    string
	Address     string
	Country     string
}

// errNoUsableCircuit means tor currently has no circuit whose exit this
// instance can honestly be said to go out through. It is a normal transient
// right after bootstrap and right after a NEWNYM.
var errNoUsableCircuit = errors.New("tor: no usable exit circuit yet")

// ExitNode resolves the exit relay this instance is currently exiting through.
//
// This reads the exit relay's advertised address from tor's own consensus view,
// which costs no Tor bandwidth — unlike fetching an IP-echo URL through the
// circuit. It is the real exit address a target site would see.
//
// The answer has to be *stable*, not merely current. Tor holds several built
// circuits at once and keeps building more preemptively, so naming whichever is
// newest makes the reported exit flip between relays no traffic ever used —
// which is what makes an instance look like it has two exits at once. selectExit
// holds the choice still; see it for the ordering.
func (c *Control) ExitNode() (ExitNode, error) {
	circuits, err := c.GetInfo("circuit-status")
	if err != nil {
		return ExitNode{}, err
	}
	// Best effort: without stream-status the choice falls back to the circuit
	// set alone, which is what happens between requests anyway.
	streams, _ := c.GetInfo("stream-status")

	fp := c.selectExit(parseCircuits(circuits), streams)
	if fp == "" {
		return ExitNode{}, errNoUsableCircuit
	}
	// Record the choice before the lookups so a failing consensus query leaves
	// the next call on the same circuit rather than moving it.
	c.lastExit = fp

	desc, err := c.GetInfo("ns/id/" + fp)
	if err != nil {
		return ExitNode{Fingerprint: fp}, err
	}
	node := parseNetworkStatus(desc)
	node.Fingerprint = fp

	// Country is a separate lookup and is best-effort: tor only answers when a
	// GeoIP database is present in the image.
	if node.Address != "" {
		if cc, err := c.GetInfo("ip-to-country/" + node.Address); err == nil {
			node.Country = strings.ToUpper(strings.TrimSpace(cc))
		}
	}
	return node, nil
}

// circuit is one BUILT, exit-bearing circuit as circuit-status reported it.
type circuit struct {
	id      string
	exit    string
	created time.Time
}

// selectExit picks which circuit's exit to report, most trustworthy first:
//
//  1. the circuit carrying a stream — the only one tor has committed traffic to;
//  2. the exit reported last time, as long as a circuit to it still stands, so
//     an idle instance keeps naming one identity;
//  3. the newest circuit, when there is nothing better to go on.
//
// Circuits built before the last NEWNYM are excluded outright. That signal marks
// every existing circuit unusable for new streams, so their exits are no longer
// where this instance goes out; reporting one alongside a replacement circuit is
// what made a rotation look like it toggled between two relays.
func (c *Control) selectExit(circuits []circuit, streamStatus string) string {
	usable := make([]circuit, 0, len(circuits))
	for _, cc := range circuits {
		if c.lastNewnym.IsZero() || cc.created.After(c.lastNewnym) {
			usable = append(usable, cc)
		}
	}
	if len(usable) == 0 {
		return ""
	}

	if id := attachedCircuitID(streamStatus); id != "" {
		for _, cc := range usable {
			if cc.id == id {
				return cc.exit
			}
		}
	}
	if c.lastExit != "" {
		for _, cc := range usable {
			if cc.exit == c.lastExit {
				return cc.exit
			}
		}
	}

	// A tie — including a payload with no TIME_CREATED at all — falls back to
	// tor's own listing order, whose last entry is the most recent.
	newest := usable[0]
	for _, cc := range usable[1:] {
		if !cc.created.Before(newest.created) {
			newest = cc
		}
	}
	return newest.exit
}

// attachedCircuitID returns the circuit carrying the most recently attached
// stream, or "" when no stream is attached — between requests there usually is
// none.
//
// stream-status lines look like:
//
//	<streamID> SUCCEEDED <circuitID> example.com:443
func attachedCircuitID(streamStatus string) string {
	var circuitID string
	for line := range strings.SplitSeq(streamStatus, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		// NEW and NEWRESOLVE streams have no circuit yet; their circuit id is 0.
		if fields[1] != "SUCCEEDED" || fields[2] == "0" {
			continue
		}
		circuitID = fields[2]
	}
	return circuitID
}

// exitPurposes are the circuit purposes that carry exit traffic.
//
// CONFLUX_LINKED is not an exotic case: conflux is on by default in current tor,
// and once a set is linked those legs are what streams actually ride. A resolver
// that only accepts GENERAL reads the preemptive circuits tor keeps around and
// never the ones in use — it names an exit the traffic is not leaving through,
// and follows tor between them as they are rebuilt. Legs of one conflux set
// share their exit by construction, so they all resolve to the same relay.
var exitPurposes = map[string]bool{
	"PURPOSE=GENERAL":        true,
	"PURPOSE=CONFLUX_LINKED": true,
}

// parseCircuits pulls the exit-bearing circuits out of a circuit-status payload,
// keeping tor's own listing order. Lines look like:
//
//	5 BUILT $AAAA~guard,$BBBB~mid,$CCCC~exit BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:12:33.123456
//
// Anything not BUILT has no usable path yet. Other purposes (HS_VANGUARDS,
// HS_CLIENT_INTRO, CONFLUX_UNLINKED, …) either never exit or cannot carry a
// stream yet, and an IS_INTERNAL circuit has no exit hop at all whatever its
// purpose says.
func parseCircuits(circuitStatus string) []circuit {
	var out []circuit
	for line := range strings.SplitSeq(circuitStatus, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || fields[1] != "BUILT" {
			continue
		}

		var (
			exits    bool
			internal bool
			created  time.Time
		)
		for _, field := range fields[3:] {
			switch {
			case exitPurposes[field]:
				exits = true
			case strings.HasPrefix(field, "BUILD_FLAGS="):
				internal = strings.Contains(field, "IS_INTERNAL")
			default:
				if v, ok := strings.CutPrefix(field, "TIME_CREATED="); ok {
					created = parseTimeCreated(v)
				}
			}
		}
		if !exits || internal {
			continue
		}
		if exit := lastHopFingerprint(fields[2]); exit != "" {
			out = append(out, circuit{id: fields[0], exit: exit, created: created})
		}
	}
	return out
}

// timeCreatedLayout is tor's ISOTime2Frac form. It carries no zone suffix and is
// always UTC, so it has to be parsed as UTC rather than local time.
const timeCreatedLayout = "2006-01-02T15:04:05.999999"

// parseTimeCreated reads a TIME_CREATED value. An unparseable one yields the
// zero time, meaning "age unknown" — which keeps the circuit out of the running
// once a NEWNYM has happened, because an exit that cannot be shown to be fresh
// must not be reported as one.
func parseTimeCreated(value string) time.Time {
	created, err := time.ParseInLocation(timeCreatedLayout, unquoteControlValue(value), time.UTC)
	if err != nil {
		return time.Time{}
	}
	return created
}

// lastHopFingerprint extracts the exit fingerprint from a circuit path.
//
// Each hop is "$FINGERPRINT~Nickname" or "$FINGERPRINT=Nickname" — named relays
// use '='.
func lastHopFingerprint(path string) string {
	hops := strings.Split(path, ",")
	last := strings.TrimPrefix(hops[len(hops)-1], "$")
	if i := strings.IndexAny(last, "~="); i >= 0 {
		last = last[:i]
	}
	return last
}

// parseNetworkStatus pulls the nickname and address out of an "r" line:
//
//	r Nickname base64id base64digest 2026-07-27 12:00:00 1.2.3.4 9001 9030
func parseNetworkStatus(desc string) ExitNode {
	var node ExitNode
	for line := range strings.SplitSeq(desc, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] != "r" {
			continue
		}
		node.Nickname = fields[1]
		node.Address = fields[6]
		return node
	}
	return node
}

// command writes one command and reads its complete reply.
func (c *Control) command(cmd string) (string, error) {
	if c.conn == nil {
		return "", errors.New("tor: control connection is closed")
	}
	if _, err := fmt.Fprintf(c.conn, "%s\r\n", cmd); err != nil {
		return "", fmt.Errorf("write %s: %w", commandName(cmd), err)
	}
	code, reply, err := c.readReply()
	if err != nil {
		return "", fmt.Errorf("%s: %w", commandName(cmd), err)
	}
	if code < 200 || code >= 300 {
		return "", &ControlError{Code: code, Reply: reply, Cmd: commandName(cmd)}
	}
	return reply, nil
}

// readReply reads a control-protocol reply.
//
// Replies are a sequence of lines whose 4th byte is '-' or '+' for
// continuations and ' ' on the final line. A '+' line introduces a dot-quoted
// multi-line payload terminated by a lone ".".
func (c *Control) readReply() (code int, reply string, err error) {
	var (
		body  strings.Builder
		first = true
	)
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return 0, "", fmt.Errorf("read reply: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			return 0, "", fmt.Errorf("short control reply %q", line)
		}

		n, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, "", fmt.Errorf("bad status code in %q", line)
		}
		if first || n >= 400 {
			// Keep the first code, but let an error code anywhere in a
			// multi-line reply win — that is the one worth reporting.
			code = n
			first = false
		}

		sep, rest := line[3], line[4:]
		switch sep {
		case ' ':
			writeReplyLine(&body, rest)
			return code, body.String(), nil
		case '-':
			writeReplyLine(&body, rest)
		case '+':
			writeReplyLine(&body, rest)
			data, err := c.readDotQuoted()
			if err != nil {
				return 0, "", err
			}
			body.WriteString("\n")
			body.WriteString(data)
		default:
			return 0, "", fmt.Errorf("bad separator %q in control reply", sep)
		}
	}
}

// readDotQuoted reads a '+' payload up to the terminating lone ".".
func (c *Control) readDotQuoted() (string, error) {
	var sb strings.Builder
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read multi-line payload: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "." {
			return sb.String(), nil
		}
		// A leading dot is escaped by doubling it.
		line = strings.TrimPrefix(line, ".")
		sb.WriteString(line)
		sb.WriteString("\n")
	}
}

func writeReplyLine(sb *strings.Builder, line string) {
	if sb.Len() > 0 {
		sb.WriteString("\n")
	}
	sb.WriteString(line)
}

// parseGetInfo extracts the value for key from a GETINFO reply, which is either
// "key=value" on one line or "key=" followed by a multi-line payload.
func parseGetInfo(reply, key string) (string, error) {
	lines := strings.Split(reply, "\n")
	for i, line := range lines {
		value, ok := strings.CutPrefix(line, key+"=")
		if !ok {
			continue
		}
		if value != "" {
			return unquoteControlValue(value), nil
		}
		// Multi-line form: everything up to the trailing "OK" belongs to us.
		rest := lines[i+1:]
		if n := len(rest); n > 0 && strings.EqualFold(strings.TrimSpace(rest[n-1]), "OK") {
			rest = rest[:n-1]
		}
		return strings.TrimRight(strings.Join(rest, "\n"), "\n"), nil
	}
	return "", fmt.Errorf("tor: GETINFO reply has no %q: %q", key, reply)
}

// quoteControlValue wraps a value in the control protocol's QuotedString form
// when it contains anything that would otherwise be misparsed. Session keys and
// exit policies are caller-supplied, so this must never be skipped.
func quoteControlValue(v string) string {
	if !strings.ContainsAny(v, " \t\"\\\r\n") {
		return v
	}
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range v {
		switch r {
		case '"', '\\':
			sb.WriteByte('\\')
			sb.WriteRune(r)
		case '\r', '\n':
			// Newlines would terminate the command line entirely.
			continue
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func unquoteControlValue(v string) string {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}
	if unquoted, err := strconv.Unquote(v); err == nil {
		return unquoted
	}
	return v[1 : len(v)-1]
}

func commandName(cmd string) string {
	if i := strings.IndexByte(cmd, ' '); i > 0 {
		return cmd[:i]
	}
	return cmd
}
