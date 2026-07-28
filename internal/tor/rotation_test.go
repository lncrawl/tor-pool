package tor

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBusyCircuitsIncludeStreamsStillConnecting(t *testing.T) {
	// A stream that has been given a circuit but has not connected yet is a
	// request in flight. Only SUCCEEDED counts as "traffic is confirmed here",
	// but every one of these means "do not cut this circuit".
	status := strings.Join([]string{
		"1 NEW 0 example.com:443",
		"2 SENTCONNECT 6 example.com:443",
		"3 SUCCEEDED 7 other.example:443",
		"4 RESOLVE_WAIT 8 third.example:80",
		"5 NEWRESOLVE 0 fourth.example",
	}, "\n")

	if got := attachedCircuitIDs(status); !slices.Equal(got, []string{"7"}) {
		t.Errorf("attached = %v, want only the SUCCEEDED stream's circuit 7", got)
	}
	want := []string{"6", "7", "8"}
	if got := busyCircuitIDs(status); !slices.Equal(got, want) {
		t.Errorf("busy = %v, want %v", got, want)
	}
}

func TestCloseRetiredCircuitsSparesAConnectingStream(t *testing.T) {
	// The regression this guards: circuit 2 carries a request whose exit has not
	// finished connecting to the destination, a phase that lasts as long as the
	// destination takes to answer. Closing it failed the request outright, which
	// is what made rotating under load drop a few percent of traffic.
	raw := "250+circuit-status=\r\n" +
		"1 BUILT $AAAA~guard,$CCCC~old PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:10:00.000000\r\n" +
		"2 BUILT $DDDD~guard,$FFFF~busy PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:11:00.000000\r\n" +
		".\r\n250 OK\r\n" +
		"250-stream-status=42 SENTCONNECT 2 example.com:443\r\n250 OK\r\n" +
		"250 OK\r\n" // the one CLOSECIRCUIT

	c := reply(raw)
	c.conn = discardConn{}
	c.authenticated = true
	c.lastNewnym = time.Date(2026, 7, 28, 9, 15, 0, 0, time.UTC)

	closed, err := c.CloseRetiredCircuits()
	if err != nil {
		t.Fatalf("CloseRetiredCircuits: %v", err)
	}
	if closed != 1 {
		t.Errorf("closed = %d, want 1 (only the idle circuit)", closed)
	}
}

func TestCloseRetiredCircuitsClosesNothingWithoutStreamStatus(t *testing.T) {
	// Without the stream list there is no way to tell a live request's circuit
	// from an abandoned one. Closing them anyway would drop whatever is in
	// flight, so nothing is closed and the error is reported.
	raw := "250+circuit-status=\r\n" +
		"1 BUILT $AAAA~guard,$CCCC~old PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:10:00.000000\r\n" +
		".\r\n250 OK\r\n" +
		"552 Unrecognized key \"stream-status\"\r\n"

	c := reply(raw)
	c.conn = discardConn{}
	c.authenticated = true
	c.lastNewnym = time.Date(2026, 7, 28, 9, 15, 0, 0, time.UTC)

	closed, err := c.CloseRetiredCircuits()
	if err == nil {
		t.Error("expected an error when the stream list is unavailable")
	}
	if closed != 0 {
		t.Errorf("closed = %d, want 0", closed)
	}
}

func TestCloseCircuitsExceptExitLeavesThePinnedOne(t *testing.T) {
	// A pin only governs circuits tor builds afterwards, so the standing ones
	// have to go — except the one already on the pinned relay, and any carrying
	// traffic.
	raw := "250+circuit-status=\r\n" +
		"1 BUILT $AAAA~guard,$PINNED~keep PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:10:00.000000\r\n" +
		"2 BUILT $BBBB~guard,$OTHER~drop PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:11:00.000000\r\n" +
		"3 BUILT $CCCC~guard,$THIRD~busy PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:12:00.000000\r\n" +
		".\r\n250 OK\r\n" +
		"250-stream-status=42 SUCCEEDED 3 example.com:443\r\n250 OK\r\n" +
		"250 OK\r\n" // the one CLOSECIRCUIT

	c := reply(raw)
	c.conn = discardConn{}
	c.authenticated = true

	closed, err := c.CloseCircuitsExceptExit("PINNED")
	if err != nil {
		t.Fatalf("CloseCircuitsExceptExit: %v", err)
	}
	if closed != 1 {
		t.Errorf("closed = %d, want 1 (circuit 2 only)", closed)
	}
}

func TestSelectExitConfirmsOnlyWithAStream(t *testing.T) {
	var c Control

	exit, confirmed := c.selectExit(parseCircuits(testCircuits), "42 SUCCEEDED 1 example.com:443")
	if exit != "CCCC" || !confirmed {
		t.Errorf("with a stream: exit = %q confirmed = %v, want CCCC true", exit, confirmed)
	}

	// No stream: the answer is inferred from whichever circuits tor is holding,
	// and callers must be told so rather than publishing a guess as fact.
	exit, confirmed = c.selectExit(parseCircuits(testCircuits), "")
	if exit == "" || confirmed {
		t.Errorf("without a stream: exit = %q confirmed = %v, want a guess and false", exit, confirmed)
	}
}

func TestCommandMarksTheConnectionBrokenOnIOFailure(t *testing.T) {
	// A truncated reply leaves the stream out of sync: the rest of it would be
	// read as the next command's answer. The connection has to be discarded.
	c := reply("250-partial and then the socket dies")
	c.conn = discardConn{}
	c.authenticated = true

	if _, err := c.GetInfo("circuit-status"); err == nil {
		t.Fatal("expected an error from a truncated reply")
	}
	if !c.Broken() {
		t.Error("connection should be marked broken")
	}
	if _, err := c.GetInfo("version"); err == nil {
		t.Error("a broken connection must refuse further commands")
	}
}

func TestControlErrorLeavesTheConnectionUsable(t *testing.T) {
	// Tor saying no is a complete, well-framed answer; only I/O trouble poisons
	// the stream.
	c := reply("552 Unrecognized key \"nope\"\r\n250-version=0.4.9.11\r\n250 OK\r\n")
	c.conn = discardConn{}
	c.authenticated = true

	if _, err := c.GetInfo("nope"); err == nil {
		t.Fatal("expected an error for an unrecognised key")
	}
	if c.Broken() {
		t.Fatal("a 552 must not break the connection")
	}
	if _, err := c.GetInfo("version"); err != nil {
		t.Errorf("the next command should still work: %v", err)
	}
}

func TestSetConfAllSendsOneCommand(t *testing.T) {
	// Options that only make sense together have to be applied together: a
	// StrictNodes that lands before its ExitNodes leaves tor unable to build
	// anything at all in between.
	var sent strings.Builder
	c := reply("250 OK\r\n")
	c.conn = recordConn{&sent}
	c.authenticated = true

	if err := c.SetConfAll(
		ConfValue{"ExitNodes", "$AAAA"},
		ConfValue{"ExcludeExitNodes", ""},
		ConfValue{"StrictNodes", "1"},
	); err != nil {
		t.Fatalf("SetConfAll: %v", err)
	}

	want := "SETCONF ExitNodes=$AAAA ExcludeExitNodes StrictNodes=1\r\n"
	if sent.String() != want {
		t.Errorf("sent %q, want %q", sent.String(), want)
	}
}
