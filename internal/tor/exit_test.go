package tor

import "testing"

const testCircuits = `1 BUILT $AAAA~guard,$BBBB~mid,$CCCC~exitone PURPOSE=GENERAL
2 BUILT $DDDD~guard,$EEEE~mid,$FFFF~exittwo PURPOSE=GENERAL
3 BUILT $GGGG~internal PURPOSE=HS_CLIENT_INTRO`

func TestAttachedExitPrefersCircuitCarryingAStream(t *testing.T) {
	// Circuit 2 is newer, but the live stream is on circuit 1 — so circuit 1's
	// exit is where traffic is actually leaving.
	streams := "42 SUCCEEDED 1 example.com:443"

	if got := attachedExitFingerprint(streams, testCircuits); got != "CCCC" {
		t.Errorf("fingerprint = %q, want CCCC (the circuit with the stream)", got)
	}
}

func TestAttachedExitIgnoresUnattachedStreams(t *testing.T) {
	// A NEW stream has no circuit yet; its circuit id is 0.
	streams := "42 NEW 0 example.com:443\n43 NEWRESOLVE 0 example.com"

	if got := attachedExitFingerprint(streams, testCircuits); got != "" {
		t.Errorf("fingerprint = %q, want empty so the caller falls back", got)
	}
}

func TestAttachedExitWithNoStreams(t *testing.T) {
	if got := attachedExitFingerprint("", testCircuits); got != "" {
		t.Errorf("fingerprint = %q, want empty", got)
	}
}

func TestAttachedExitUsesMostRecentStream(t *testing.T) {
	streams := "42 SUCCEEDED 1 old.example:443\n43 SUCCEEDED 2 new.example:443"

	if got := attachedExitFingerprint(streams, testCircuits); got != "FFFF" {
		t.Errorf("fingerprint = %q, want FFFF from the latest stream", got)
	}
}

func TestAttachedExitUnknownCircuitID(t *testing.T) {
	// A stream can reference a circuit that has already closed.
	streams := "42 SUCCEEDED 99 example.com:443"

	if got := attachedExitFingerprint(streams, testCircuits); got != "" {
		t.Errorf("fingerprint = %q, want empty for an unknown circuit", got)
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
