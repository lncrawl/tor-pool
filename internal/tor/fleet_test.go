package tor

import (
	"io"
	"log/slog"
	"testing"
)

func TestFreeIndexReusesRetiredSlots(t *testing.T) {
	// Every index maps to a fixed pair of ports drawn from two blocks a fixed
	// distance apart. Handing them out from an ever-growing counter eventually
	// gives an instance a SOCKS port that is another instance's control port, in
	// a pool that never exceeded its configured size — it just resized a lot.
	f := NewFleet(FleetOptions{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, index := range []int{0, 1, 2} {
		f.instances[index] = NewInstance("tor", InstanceConfig{Index: index}, log)
	}
	if got := f.freeIndexLocked(); got != 3 {
		t.Errorf("free index = %d, want 3", got)
	}

	delete(f.instances, 1)
	if got := f.freeIndexLocked(); got != 1 {
		t.Errorf("free index = %d, want the retired slot 1 back", got)
	}
}
