package tor

import (
	"strings"
	"testing"
	"time"
)

func testInstance() InstanceConfig {
	return InstanceConfig{
		Index:               3,
		DataDirectory:       "/var/lib/tor/3",
		SocksPort:           19003,
		ControlPort:         19503,
		MaxCircuitDirtiness: time.Hour,
	}
}

func TestTorrcHoldsCircuitsForStickiness(t *testing.T) {
	// Without this, tor's 10-minute default would swap the exit IP under a
	// session that never asked to rotate.
	rc := testInstance().Torrc()
	if !strings.Contains(rc, "MaxCircuitDirtiness 3600") {
		t.Errorf("circuit lifetime not rendered in seconds:\n%s", rc)
	}
}

func TestTorrcOmitsCircuitLifetimeWhenUnset(t *testing.T) {
	ic := testInstance()
	ic.MaxCircuitDirtiness = 0
	if strings.Contains(ic.Torrc(), "MaxCircuitDirtiness") {
		t.Error("an unset lifetime should leave tor's default in place")
	}
}

func TestTorrcBindsPortsToLoopbackOnly(t *testing.T) {
	rc := testInstance().Torrc()

	// Invariant: instance ports are never reachable from outside the
	// container, which is what makes password-less cookie auth safe.
	if !strings.Contains(rc, "SocksPort 127.0.0.1:19003") {
		t.Errorf("SOCKS port must bind loopback:\n%s", rc)
	}
	if !strings.Contains(rc, "ControlPort 127.0.0.1:19503") {
		t.Errorf("control port must bind loopback:\n%s", rc)
	}
	if strings.Contains(rc, "0.0.0.0") {
		t.Errorf("no instance port may bind a wildcard address:\n%s", rc)
	}
}

func TestTorrcUsesCookieAuthAndNoPassword(t *testing.T) {
	rc := testInstance().Torrc()
	if !strings.Contains(rc, "CookieAuthentication 1") {
		t.Error("cookie authentication must be enabled")
	}
	if strings.Contains(rc, "HashedControlPassword") {
		t.Error("no password hash should ever be written")
	}
}

func TestTorrcRestrictsSocksPolicy(t *testing.T) {
	rc := testInstance().Torrc()
	if !strings.Contains(rc, "SocksPolicy accept 127.0.0.1") {
		t.Error("only torpool itself may use the instance SOCKS port")
	}
	if !strings.Contains(rc, "SocksPolicy reject *") {
		t.Error("everything else must be rejected")
	}
}

func TestTorrcExitPolicyIsOmittedWhenUnset(t *testing.T) {
	rc := testInstance().Torrc()
	for _, unwanted := range []string{"ExitNodes", "ExcludeExitNodes", "StrictNodes"} {
		if strings.Contains(rc, unwanted) {
			t.Errorf("%s should be absent when not configured:\n%s", unwanted, rc)
		}
	}
}

func TestTorrcRendersExitPolicy(t *testing.T) {
	ic := testInstance()
	ic.ExitNodes = "{us},{ca}"
	ic.ExcludeExitNodes = "{ru}"
	ic.StrictNodes = true

	rc := ic.Torrc()
	for _, want := range []string{"ExitNodes {us},{ca}", "ExcludeExitNodes {ru}", "StrictNodes 1"} {
		if !strings.Contains(rc, want) {
			t.Errorf("missing %q:\n%s", want, rc)
		}
	}
}

func TestTorrcAppendsExtraConfig(t *testing.T) {
	ic := testInstance()
	ic.ExtraConfig = "  MaxCircuitDirtiness 60\n"
	rc := ic.Torrc()
	if !strings.Contains(rc, "MaxCircuitDirtiness 60") {
		t.Errorf("extra config not appended:\n%s", rc)
	}
}

func TestInstancePaths(t *testing.T) {
	ic := testInstance()
	if got, want := ic.CookiePath(), "/var/lib/tor/3/control_auth_cookie"; got != want {
		t.Errorf("CookiePath() = %q, want %q", got, want)
	}
	if got, want := ic.TorrcPath(), "/var/lib/tor/3/torrc"; got != want {
		t.Errorf("TorrcPath() = %q, want %q", got, want)
	}
	if got, want := ic.SocksAddr(), "127.0.0.1:19003"; got != want {
		t.Errorf("SocksAddr() = %q, want %q", got, want)
	}
	if got, want := ic.ControlAddr(), "127.0.0.1:19503"; got != want {
		t.Errorf("ControlAddr() = %q, want %q", got, want)
	}
}
