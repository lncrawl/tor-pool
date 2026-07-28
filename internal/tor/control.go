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
	"sync"
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

// commandTimeout bounds the I/O of a single control command.
//
// Without it a tor that accepts the connection but stops answering wedges the
// caller forever while it holds the instance's control lock — which took the
// pool's maintenance loop with it. A local socket that cannot answer in this
// long is not slow, it is broken.
const commandTimeout = 20 * time.Second

// Control is a client for a single tor control port.
//
// It is not safe for concurrent use: the control protocol is a synchronous
// request/reply stream over one connection, so callers must serialise commands.
// The pool holds one Control per instance and guards it with the instance lock.
// The one exception is the NEWNYM cooldown, which is readable at any time so a
// caller can decide whether to wait without taking that lock.
type Control struct {
	conn net.Conn
	r    *bufio.Reader

	authenticated bool

	// broken records that a command failed mid-exchange. The reply stream is
	// then out of sync — the next command would read the previous one's tail —
	// so the connection has to be discarded rather than reused.
	broken bool

	// newnymMu guards lastNewnym alone, which NewnymWait reads without holding
	// the instance's control lock.
	newnymMu sync.Mutex

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
		c.newnymMu.Lock()
		c.lastNewnym = time.Now()
		c.newnymMu.Unlock()
		// The exit we were reporting is exactly the one this signal retired.
		c.lastExit = ""
	}
	return nil
}

// newnymAt returns when this connection last signalled NEWNYM.
func (c *Control) newnymAt() time.Time {
	c.newnymMu.Lock()
	defer c.newnymMu.Unlock()
	return c.lastNewnym
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

// ConfValue is one SETCONF assignment. An empty Value resets the option to its
// compiled-in default.
type ConfValue struct{ Key, Value string }

// SetConf applies configuration at runtime, e.g. SetConf("ExitNodes", "{us}").
// An empty value resets the option to its default.
func (c *Control) SetConf(key, value string) error {
	return c.SetConfAll(ConfValue{key, value})
}

// SetConfAll applies several options in one SETCONF.
//
// One command rather than several matters for options that only make sense
// together: setting StrictNodes before ExitNodes leaves tor briefly refusing to
// build any circuit at all, and setting it after leaves a window where the pin
// is advisory.
func (c *Control) SetConfAll(values ...ConfValue) error {
	if !c.authenticated {
		return ErrNotAuthenticated
	}
	if len(values) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString("SETCONF")
	for _, v := range values {
		sb.WriteByte(' ')
		sb.WriteString(v.Key)
		if v.Value != "" {
			sb.WriteByte('=')
			sb.WriteString(quoteControlValue(v.Value))
		}
	}
	_, err := c.command(sb.String())
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
	last := c.newnymAt()
	if last.IsZero() {
		return 0
	}
	if remaining := NewnymCooldown - time.Since(last); remaining > 0 {
		return remaining
	}
	return 0
}

// Newnym waits out any remaining cooldown, then requests a new circuit. It
// returns early if ctx is cancelled while waiting.
//
// Prefer Instance.Newnym, which does the waiting without holding the instance's
// control lock; this blocks with it held.
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
// The second return value says whether a stream confirmed the answer. Only a
// circuit tor has actually attached traffic to proves where this instance goes
// out; anything else is inferred from the circuits standing around, several of
// which tor built preemptively and no request will ever use. Callers must not
// let an inferred answer overwrite a confirmed one — that is what made a
// rotation look like the exit IP jumped a couple of times before settling.
func (c *Control) ExitNode() (node ExitNode, confirmed bool, err error) {
	circuits, err := c.GetInfo("circuit-status")
	if err != nil {
		return ExitNode{}, false, err
	}
	// Best effort: without stream-status the choice falls back to the circuit
	// set alone, which is what happens between requests anyway.
	streams, _ := c.GetInfo("stream-status")

	fp, confirmed := c.selectExit(parseCircuits(circuits), streams)
	if fp == "" {
		return ExitNode{}, false, errNoUsableCircuit
	}
	// Record the choice before the lookups so a failing consensus query leaves
	// the next call on the same circuit rather than moving it.
	c.lastExit = fp

	desc, err := c.GetInfo("ns/id/" + fp)
	if err != nil {
		return ExitNode{Fingerprint: fp}, confirmed, err
	}
	node = parseNetworkStatus(desc)
	node.Fingerprint = fp

	// Country is a separate lookup and is best-effort: tor only answers when a
	// GeoIP database is present in the image.
	if node.Address != "" {
		if cc, err := c.GetInfo("ip-to-country/" + node.Address); err == nil {
			node.Country = strings.ToUpper(strings.TrimSpace(cc))
		}
	}
	return node, confirmed, nil
}

// circuit is one BUILT, exit-bearing circuit as circuit-status reported it.
type circuit struct {
	id      string
	exit    string
	purpose string
	created time.Time
}

// canCarryStream reports whether tor could attach a new stream to this circuit.
// An unlinked conflux leg cannot: it is still negotiating with its partner.
func (c circuit) canCarryStream() bool { return c.purpose != "CONFLUX_UNLINKED" }

// selectExit picks which circuit's exit to report, most trustworthy first:
//
//  1. the circuit carrying a stream — the only one tor has committed traffic to,
//     and the only answer that comes back confirmed;
//  2. the exit reported last time, as long as a circuit to it still stands, so
//     an idle instance keeps naming one identity;
//  3. the newest circuit, when there is nothing better to go on.
//
// Only the first is evidence. The other two are inferred from circuits tor may
// well have built preemptively and never used, so they come back unconfirmed and
// must never displace a confirmed answer.
//
// Circuits built before the last NEWNYM are excluded outright. That signal marks
// every existing circuit unusable for new streams, so their exits are no longer
// where this instance goes out; reporting one alongside a replacement circuit is
// what made a rotation look like it toggled between two relays.
func (c *Control) selectExit(circuits []circuit, streamStatus string) (exit string, confirmed bool) {
	newnym := c.newnymAt()

	usable := make([]circuit, 0, len(circuits))
	for _, cc := range circuits {
		if !cc.canCarryStream() {
			continue
		}
		if newnym.IsZero() || cc.created.After(newnym) {
			usable = append(usable, cc)
		}
	}
	if len(usable) == 0 {
		return "", false
	}

	if ids := attachedCircuitIDs(streamStatus); len(ids) > 0 {
		// The most recently attached stream is the best evidence of where this
		// instance is going out right now.
		attached := ids[len(ids)-1]
		for _, cc := range usable {
			if cc.id == attached {
				return cc.exit, true
			}
		}
	}
	if c.lastExit != "" {
		for _, cc := range usable {
			if cc.exit == c.lastExit {
				return cc.exit, false
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
	return newest.exit, false
}

// attachedCircuitIDs lists the circuits carrying a *connected* stream, in the
// order stream-status reported them. It is empty between requests, which is the
// normal case for an idle instance.
//
// stream-status lines look like:
//
//	<streamID> SUCCEEDED <circuitID> example.com:443
func attachedCircuitIDs(streamStatus string) []string {
	return circuitIDsWithStreams(streamStatus, true)
}

// busyCircuitIDs lists every circuit tor has a stream on, whatever state that
// stream is in.
//
// This is deliberately wider than attachedCircuitIDs. A stream that has been
// given a circuit but has not connected yet — SENTCONNECT while the exit opens
// the TCP connection, RESOLVE_WAIT while it looks the name up — is a request in
// flight, and that phase lasts as long as the destination takes to answer.
// Closing its circuit is exactly how a rotation used to drop live requests.
func busyCircuitIDs(streamStatus string) []string {
	return circuitIDsWithStreams(streamStatus, false)
}

func circuitIDsWithStreams(streamStatus string, connectedOnly bool) []string {
	var ids []string
	for line := range strings.SplitSeq(streamStatus, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		// NEW and NEWRESOLVE streams have no circuit yet; their circuit id is 0.
		if fields[2] == "0" {
			continue
		}
		if connectedOnly && fields[1] != "SUCCEEDED" {
			continue
		}
		ids = append(ids, fields[2])
	}
	return ids
}

// CloseRetiredCircuits tears down the circuits the last NEWNYM retired, and
// reports how many it closed.
//
// NEWNYM on its own is not enough. Tor marks the existing circuits unusable for
// new streams but leaves them standing, and while they stand it has no reason to
// build replacements: an idle instance sits for minutes with no circuit whose
// exit it could honestly report, and traffic has been seen still leaving through
// a retired conflux set. Closing them forces tor to rebuild immediately, which
// is what makes a rotation take effect on the next request rather than eventually.
//
// Circuits carrying a stream are left alone, whether or not that stream has
// connected yet. A proxy connection is pinned to its instance for its whole life,
// so cutting one would fail a request already in flight — including one still
// waiting on the exit to reach the destination, and an idle HTTP CONNECT tunnel
// whose stream stays open between requests.
func (c *Control) CloseRetiredCircuits() (int, error) {
	if !c.authenticated {
		return 0, ErrNotAuthenticated
	}
	newnym := c.newnymAt()
	if newnym.IsZero() {
		return 0, nil
	}

	return c.closeIdleCircuits(func(cc circuit) bool {
		return !cc.created.IsZero() && cc.created.Before(newnym)
	})
}

// CloseCircuitsExceptExit tears down every idle exit circuit that does not leave
// through the given relay, and reports how many it closed.
//
// A pin only governs the circuits tor builds afterwards. The ones already
// standing keep their own exits, and tor will happily attach the next stream to
// one of them — so a pin that does not clear them is a pin the traffic ignores.
func (c *Control) CloseCircuitsExceptExit(fingerprint string) (int, error) {
	if !c.authenticated {
		return 0, ErrNotAuthenticated
	}
	return c.closeIdleCircuits(func(cc circuit) bool { return cc.exit != fingerprint })
}

// closeIdleCircuits closes the circuits doomed reports, sparing any that carries
// a stream.
func (c *Control) closeIdleCircuits(doomed func(circuit) bool) (int, error) {
	circuits, err := c.GetInfo("circuit-status")
	if err != nil {
		return 0, err
	}
	streams, err := c.GetInfo("stream-status")
	if err != nil {
		// Without the stream list there is no way to tell a live request's
		// circuit from an abandoned one, and guessing wrong drops the request.
		// The circuits stay standing; tor retires them on its own schedule.
		return 0, fmt.Errorf("cannot tell which circuits are busy: %w", err)
	}
	busy := make(map[string]bool, 4)
	for _, id := range busyCircuitIDs(streams) {
		busy[id] = true
	}

	var (
		closed int
		errs   []error
	)
	for _, cc := range parseCircuits(circuits) {
		if busy[cc.id] || !doomed(cc) {
			continue
		}
		if _, err := c.command("CLOSECIRCUIT " + cc.id); err != nil {
			errs = append(errs, err)
			continue
		}
		closed++
	}
	return closed, errors.Join(errs...)
}

// exitPurposes are the circuit purposes that exit to the internet.
//
// The conflux ones are not an exotic case: conflux is on by default in current
// tor, and once a set is linked those legs are what streams actually ride. A
// resolver that only accepts GENERAL reads the preemptive circuits tor keeps
// around and never the ones in use — it names an exit the traffic is not leaving
// through, and follows tor between them as they are rebuilt. Legs of one conflux
// set share their exit by construction, so they all resolve to the same relay.
//
// CONFLUX_UNLINKED legs are included because they will exit once linked, which
// makes them worth retiring on rotation; canCarryStream keeps them out of the
// reported answer until then.
var exitPurposes = map[string]bool{
	"GENERAL":          true,
	"CONFLUX_LINKED":   true,
	"CONFLUX_UNLINKED": true,
}

// parseCircuits pulls the exit-bearing circuits out of a circuit-status payload,
// keeping tor's own listing order. Lines look like:
//
//	5 BUILT $AAAA~guard,$BBBB~mid,$CCCC~exit BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:12:33.123456
//
// Anything not BUILT has no usable path yet. Other purposes (HS_VANGUARDS,
// HS_CLIENT_INTRO, MEASURE_TIMEOUT, …) never exit, and an IS_INTERNAL circuit has
// no exit hop at all whatever its purpose says.
func parseCircuits(circuitStatus string) []circuit {
	var out []circuit
	for line := range strings.SplitSeq(circuitStatus, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || fields[1] != "BUILT" {
			continue
		}

		var (
			purpose  string
			internal bool
			created  time.Time
		)
		for _, field := range fields[3:] {
			switch {
			case strings.HasPrefix(field, "PURPOSE="):
				purpose = strings.TrimPrefix(field, "PURPOSE=")
			case strings.HasPrefix(field, "BUILD_FLAGS="):
				internal = strings.Contains(field, "IS_INTERNAL")
			default:
				if v, ok := strings.CutPrefix(field, "TIME_CREATED="); ok {
					created = parseTimeCreated(v)
				}
			}
		}
		if !exitPurposes[purpose] || internal {
			continue
		}
		if exit := lastHopFingerprint(fields[2]); exit != "" {
			out = append(out, circuit{
				id:      fields[0],
				exit:    exit,
				purpose: purpose,
				created: created,
			})
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

// ErrControlBroken means a previous command left the reply stream out of sync,
// so this connection can no longer be used. The instance redials rather than
// trying to recover a stream whose framing is unknown.
var ErrControlBroken = errors.New("tor: control connection is out of sync")

// Broken reports whether this connection has to be discarded.
func (c *Control) Broken() bool { return c.broken }

// command writes one command and reads its complete reply.
//
// An I/O failure part-way through poisons the connection: the reply this
// command did not finish reading would be read as the next command's, so the
// connection is marked broken instead of silently answering the wrong question.
func (c *Control) command(cmd string) (string, error) {
	if c.conn == nil {
		return "", errors.New("tor: control connection is closed")
	}
	if c.broken {
		return "", ErrControlBroken
	}

	if err := c.conn.SetDeadline(time.Now().Add(commandTimeout)); err != nil {
		c.broken = true
		return "", fmt.Errorf("set control deadline: %w", err)
	}
	defer func() { _ = c.conn.SetDeadline(time.Time{}) }()

	if _, err := fmt.Fprintf(c.conn, "%s\r\n", cmd); err != nil {
		c.broken = true
		return "", fmt.Errorf("write %s: %w", commandName(cmd), err)
	}
	code, reply, err := c.readReply()
	if err != nil {
		c.broken = true
		return "", fmt.Errorf("%s: %w", commandName(cmd), err)
	}
	// A non-2xx reply is a complete, well-framed answer: tor said no. The
	// connection stays usable.
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
