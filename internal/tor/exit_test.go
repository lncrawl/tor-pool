package tor

import (
	"slices"
	"testing"
	"time"
)

const testCircuits = `1 BUILT $AAAA~guard,$BBBB~mid,$CCCC~exitone PURPOSE=GENERAL
2 BUILT $DDDD~guard,$EEEE~mid,$FFFF~exittwo PURPOSE=GENERAL
3 BUILT $GGGG~internal PURPOSE=HS_CLIENT_INTRO`

func TestParseCircuitsKeepsOnlyBuiltGeneralCircuits(t *testing.T) {
	circuits := parseCircuits(testCircuits + "\n4 LAUNCHED $HHHH~guard PURPOSE=GENERAL")

	if len(circuits) != 2 {
		t.Fatalf("parsed %d circuits, want 2 (BUILT and GENERAL only)", len(circuits))
	}
	if circuits[0].id != "1" || circuits[0].exit != "CCCC" {
		t.Errorf("first circuit = %+v, want id 1 exiting CCCC", circuits[0])
	}
	if circuits[1].id != "2" || circuits[1].exit != "FFFF" {
		t.Errorf("second circuit = %+v, want id 2 exiting FFFF", circuits[1])
	}
}

// confluxCircuits is the shape a current tor really answers with: the circuits
// carrying traffic are CONFLUX_LINKED legs (two per set, sharing an exit), the
// GENERAL ones are preemptive, and the vanguard circuits are internal.
const confluxCircuits = `1 BUILT $AAAA~guard,$BBBB~mid,$CCCC~confluxexit BUILD_FLAGS=NEED_CAPACITY,NEED_UPTIME PURPOSE=CONFLUX_LINKED TIME_CREATED=2026-07-28T09:25:06.392590 CONFLUX_ID=64D5AAB75EDA0A9372993A1BAB602178 CONFLUX_RTT=353916
2 BUILT $DDDD~guard,$EEEE~mid,$CCCC~confluxexit BUILD_FLAGS=NEED_CAPACITY,NEED_UPTIME PURPOSE=CONFLUX_LINKED TIME_CREATED=2026-07-28T09:25:06.397111 CONFLUX_ID=64D5AAB75EDA0A9372993A1BAB602178 CONFLUX_RTT=409972
7 BUILT $AAAA~guard,$FFFF~mid,$9999~preemptive BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:25:06.415838
9 BUILT $AAAA~guard,$FFFF~mid,$8888~vanguard BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_VANGUARDS TIME_CREATED=2026-07-28T09:25:08.404148`

func TestParseCircuitsAcceptsConfluxLegs(t *testing.T) {
	circuits := parseCircuits(confluxCircuits)

	// Both conflux legs plus the preemptive GENERAL circuit; the internal
	// vanguard circuit has no exit hop and must not appear.
	var got []string
	for _, cc := range circuits {
		got = append(got, cc.id+"="+cc.exit)
	}
	want := []string{"1=CCCC", "2=CCCC", "7=9999"}
	if !slices.Equal(got, want) {
		t.Errorf("circuits = %v, want %v", got, want)
	}
}

func TestParseCircuitsSkipsInternalCircuits(t *testing.T) {
	// IS_INTERNAL circuits terminate at a rendezvous point, not an exit, whatever
	// their purpose reads.
	status := "9 BUILT $AAAA~guard,$8888~vanguard BUILD_FLAGS=IS_INTERNAL PURPOSE=GENERAL"

	if got := parseCircuits(status); len(got) != 0 {
		t.Errorf("parsed %+v, want nothing", got)
	}
}

func TestSelectExitPrefersTheStreamsConfluxLeg(t *testing.T) {
	// The GENERAL circuit is newer, but the stream rides a conflux leg — so the
	// conflux set's exit is where traffic is actually leaving.
	var c Control
	streams := "42 SUCCEEDED 2 example.com:443"

	if got := c.selectExit(parseCircuits(confluxCircuits), streams); got != "CCCC" {
		t.Errorf("exit = %q, want the conflux exit CCCC", got)
	}
}

func TestParseCircuitsReadsTimeCreated(t *testing.T) {
	circuits := parseCircuits(
		"1 BUILT $AAAA~guard,$CCCC~exit BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL " +
			"TIME_CREATED=2026-07-28T09:12:33.123456")

	if len(circuits) != 1 {
		t.Fatalf("parsed %d circuits, want 1", len(circuits))
	}
	// The timestamp has no zone suffix and must be read as UTC, not local time.
	want := time.Date(2026, 7, 28, 9, 12, 33, 123456000, time.UTC)
	if !circuits[0].created.Equal(want) {
		t.Errorf("created = %s, want %s", circuits[0].created, want)
	}
}

func TestSelectExitPrefersCircuitCarryingAStream(t *testing.T) {
	// Circuit 2 is newer, but the live stream is on circuit 1 — so circuit 1's
	// exit is where traffic is actually leaving.
	var c Control
	streams := "42 SUCCEEDED 1 example.com:443"

	if got := c.selectExit(parseCircuits(testCircuits), streams); got != "CCCC" {
		t.Errorf("exit = %q, want CCCC (the circuit with the stream)", got)
	}
}

func TestSelectExitIgnoresUnattachedStreams(t *testing.T) {
	// A NEW stream has no circuit yet; its circuit id is 0. With no attached
	// stream the newest circuit wins.
	var c Control
	streams := "42 NEW 0 example.com:443\n43 NEWRESOLVE 0 example.com"

	if got := c.selectExit(parseCircuits(testCircuits), streams); got != "FFFF" {
		t.Errorf("exit = %q, want FFFF from the newest circuit", got)
	}
}

func TestSelectExitUsesMostRecentStream(t *testing.T) {
	var c Control
	streams := "42 SUCCEEDED 1 old.example:443\n43 SUCCEEDED 2 new.example:443"

	if got := c.selectExit(parseCircuits(testCircuits), streams); got != "FFFF" {
		t.Errorf("exit = %q, want FFFF from the latest stream", got)
	}
}

func TestSelectExitIgnoresStreamOnUnknownCircuit(t *testing.T) {
	// A stream can reference a circuit that has already closed.
	var c Control
	streams := "42 SUCCEEDED 99 example.com:443"

	if got := c.selectExit(parseCircuits(testCircuits), streams); got != "FFFF" {
		t.Errorf("exit = %q, want the newest circuit's FFFF", got)
	}
}

func TestSelectExitPicksNewestByTimeCreated(t *testing.T) {
	// Listed last, but built first: order in the payload must not decide it.
	status := "1 BUILT $AAAA~guard,$CCCC~exit PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:30:00.000000\n" +
		"2 BUILT $DDDD~guard,$FFFF~exit PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:00:00.000000"

	var c Control
	if got := c.selectExit(parseCircuits(status), ""); got != "CCCC" {
		t.Errorf("exit = %q, want CCCC (created most recently)", got)
	}
}

func TestSelectExitStaysOnTheExitItAlreadyReported(t *testing.T) {
	// Tor built a newer circuit preemptively. No traffic has used it, so the
	// reported exit must not follow it — that flapping is the bug this guards.
	c := Control{lastExit: "CCCC"}
	status := testCircuits + "\n9 BUILT $IIII~guard,$JJJJ~exitthree PURPOSE=GENERAL"

	if got := c.selectExit(parseCircuits(status), ""); got != "CCCC" {
		t.Errorf("exit = %q, want CCCC held steady", got)
	}
}

func TestSelectExitMovesOnWhenItsCircuitIsGone(t *testing.T) {
	c := Control{lastExit: "ZZZZ"}

	if got := c.selectExit(parseCircuits(testCircuits), ""); got != "FFFF" {
		t.Errorf("exit = %q, want FFFF now that ZZZZ's circuit has closed", got)
	}
}

func TestSelectExitExcludesCircuitsOlderThanTheLastNewnym(t *testing.T) {
	// NEWNYM makes every pre-existing circuit unusable for new streams, so the
	// old exit must not be reported even while its circuit is still listed —
	// including when a stream is still attached to it.
	newnym := time.Date(2026, 7, 28, 9, 15, 0, 0, time.UTC)
	c := Control{lastNewnym: newnym, lastExit: "CCCC"}
	status := "1 BUILT $AAAA~guard,$CCCC~old PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:10:00.000000\n" +
		"2 BUILT $DDDD~guard,$FFFF~new PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:16:00.000000"

	if got := c.selectExit(parseCircuits(status), "42 SUCCEEDED 1 example.com:443"); got != "FFFF" {
		t.Errorf("exit = %q, want FFFF built after the rotation", got)
	}
}

func TestSelectExitReportsNothingUntilAFreshCircuitExists(t *testing.T) {
	// Right after a rotation there is genuinely no usable exit. Reporting none
	// is what keeps the retired one out of the API.
	c := Control{lastNewnym: time.Date(2026, 7, 28, 9, 15, 0, 0, time.UTC)}
	status := "1 BUILT $AAAA~guard,$CCCC~old PURPOSE=GENERAL TIME_CREATED=2026-07-28T09:10:00.000000"

	if got := c.selectExit(parseCircuits(status), ""); got != "" {
		t.Errorf("exit = %q, want empty until tor builds a replacement", got)
	}
}

func TestSelectExitWithNoCircuits(t *testing.T) {
	var c Control
	if got := c.selectExit(nil, "42 SUCCEEDED 1 example.com:443"); got != "" {
		t.Errorf("exit = %q, want empty", got)
	}
}

func TestLastHopFingerprint(t *testing.T) {
	tests := map[string]string{
		"$AAAA~guard,$BBBB~exit": "BBBB",
		"$AAAA=namedexit":        "AAAA",
		"$SINGLE~only":           "SINGLE",
	}
	for path, want := range tests {
		if got := lastHopFingerprint(path); got != want {
			t.Errorf("lastHopFingerprint(%q) = %q, want %q", path, got, want)
		}
	}
}
