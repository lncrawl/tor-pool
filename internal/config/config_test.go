package config

import (
	"strings"
	"testing"
	"time"
)

// env builds a lookupFunc over a literal map so tests never touch the real
// process environment.
func env(pairs map[string]string) lookupFunc {
	return func(key string) (string, bool) {
		v, ok := pairs[key]
		return v, ok
	}
}

func TestDefaultsAreValid(t *testing.T) {
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("default config must validate, got: %v", err)
	}
}

func TestLoadEmptyEnvYieldsDefaults(t *testing.T) {
	got, err := loadFrom(env(nil))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if got != Defaults() {
		t.Errorf("empty env should equal Defaults()\ngot:  %+v\nwant: %+v", got, Defaults())
	}
}

func TestLoadParsesOverrides(t *testing.T) {
	c, err := loadFrom(env(map[string]string{
		"POOL_SIZE":               "12",
		"SOCKS_PORT":              "1080",
		"SESSION_TTL":             "90s",
		"DEFAULT_SESSION":         "Shared",
		"TOR_STRICT_NODES":        "true",
		"QUARANTINE_FAILURES":     "9",
		"TOR_EXIT_NODES":          " {us} ",
		"MAX_REMEDIATION_BACKOFF": "1h",
		"ADMIN_USER":              "operator",
		"ADMIN_PASSWORD":          " keep spaces? no ",
		"PROXY_TOKEN":             "tp_abc",
		"LOGIN_TTL":               "8h",
		"LOGIN_RATE_LIMIT":        "3",
	}))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if c.PoolSize != 12 {
		t.Errorf("PoolSize = %d, want 12", c.PoolSize)
	}
	if c.SocksPort != 1080 {
		t.Errorf("SocksPort = %d, want 1080", c.SocksPort)
	}
	if c.SessionTTL != 90*time.Second {
		t.Errorf("SessionTTL = %s, want 90s", c.SessionTTL)
	}
	if c.DefaultSession != SessionShared {
		t.Errorf("DefaultSession = %q, want shared (case-insensitive)", c.DefaultSession)
	}
	if !c.StrictNodes {
		t.Error("StrictNodes = false, want true")
	}
	if c.QuarantineFailures != 9 {
		t.Errorf("QuarantineFailures = %d, want 9", c.QuarantineFailures)
	}
	if c.ExitNodes != "{us}" {
		t.Errorf("ExitNodes = %q, want %q (trimmed)", c.ExitNodes, "{us}")
	}
	if c.AdminUser != "operator" {
		t.Errorf("AdminUser = %q, want operator", c.AdminUser)
	}
	// Trimmed like every other string. Surrounding whitespace in a password is
	// far more likely to be a copy-paste artefact than deliberate, and a
	// credential that depends on invisible characters is unshippable.
	if c.AdminPassword != "keep spaces? no" {
		t.Errorf("AdminPassword = %q, want it trimmed", c.AdminPassword)
	}
	if c.ProxyToken != "tp_abc" {
		t.Errorf("ProxyToken = %q, want tp_abc", c.ProxyToken)
	}
	if c.LoginTTL != 8*time.Hour {
		t.Errorf("LoginTTL = %s, want 8h", c.LoginTTL)
	}
	if c.LoginRateLimit != 3 {
		t.Errorf("LoginRateLimit = %d, want 3", c.LoginRateLimit)
	}
}

// The error must never carry the value, or the password lands in stderr and in
// `docker logs`. envString cannot error, which is what makes this hold.
func TestPasswordNeverAppearsInAnError(t *testing.T) {
	secret := "s3cr3t-do-not-log"
	_, err := loadFrom(env(map[string]string{
		"ADMIN_PASSWORD": secret,
		// Something else must fail so there is an error to inspect at all.
		"POOL_SIZE": "not-a-number",
	}))
	if err == nil {
		t.Fatal("expected an error from POOL_SIZE")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the password appeared in an error: %v", err)
	}
}

func TestDrainOnRotateIsOnUnlessDisabled(t *testing.T) {
	if !Defaults().DrainOnRotate {
		t.Error("DrainOnRotate defaults to false, want true")
	}

	c, err := loadFrom(env(map[string]string{"DRAIN_ON_ROTATE": "false"}))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if c.DrainOnRotate {
		t.Error("DrainOnRotate = true, want false when disabled explicitly")
	}
}

func TestExitTTLZeroIsValidAndDisablesTheSchedule(t *testing.T) {
	// 0 is how an operator keeps an exit until it fails or is rotated by hand, so
	// it has to validate; a negative one is a typo for that and must not.
	c, err := loadFrom(env(map[string]string{"EXIT_TTL": "0s"}))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if c.ExitTTL != 0 {
		t.Errorf("ExitTTL = %s, want 0", c.ExitTTL)
	}

	if _, err := loadFrom(env(map[string]string{"EXIT_TTL": "-5m"})); err == nil {
		t.Error("expected an error for a negative EXIT_TTL")
	}
}

func TestEmptyHTTPPortDisablesListener(t *testing.T) {
	c, err := loadFrom(env(map[string]string{"HTTP_PORT": ""}))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if c.HTTPPort != 0 {
		t.Errorf("HTTPPort = %d, want 0 (disabled)", c.HTTPPort)
	}
	if c.SocksPort == 0 {
		t.Error("SOCKS listener should survive an empty HTTP_PORT")
	}
}

func TestBareNumberIsNotADuration(t *testing.T) {
	// "60" must not silently become 60 nanoseconds.
	_, err := loadFrom(env(map[string]string{"SESSION_TTL": "60"}))
	if err == nil {
		t.Fatal("expected an error for SESSION_TTL=60")
	}
	if !strings.Contains(err.Error(), "SESSION_TTL") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

func TestInvalidValuesAreReportedTogether(t *testing.T) {
	_, err := loadFrom(env(map[string]string{
		"POOL_SIZE":       "not-a-number",
		"DEFAULT_SESSION": "sticky",
	}))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"POOL_SIZE", "DEFAULT_SESSION"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s, got: %v", want, err)
		}
	}
}

func TestInstancePortsUseSeparateBlocks(t *testing.T) {
	c := Defaults()
	if got, want := c.InstanceSocksPort(0), 19000; got != want {
		t.Errorf("InstanceSocksPort(0) = %d, want %d", got, want)
	}
	if got, want := c.InstanceControlPort(0), 19500; got != want {
		t.Errorf("InstanceControlPort(0) = %d, want %d", got, want)
	}
	// The two blocks must never interleave, whatever the pool size.
	c.PoolSize = instancePortBlock
	if c.InstanceSocksPort(c.PoolSize-1) >= c.InstanceControlPort(0) {
		t.Error("SOCKS block overlaps the control block at maximum pool size")
	}
}

func TestListenerCollidingWithInstanceRangeIsRejected(t *testing.T) {
	// A pool this size reaches up to 19099 for SOCKS, so a listener at
	// 19050 would be bound twice.
	_, err := loadFrom(env(map[string]string{
		"POOL_SIZE":  "100",
		"SOCKS_PORT": "19050",
	}))
	if err == nil {
		t.Fatal("expected a collision error")
	}
	if !strings.Contains(err.Error(), "collides") {
		t.Errorf("error should explain the collision, got: %v", err)
	}
}

func TestListenerCollidingWithControlRangeIsRejected(t *testing.T) {
	_, err := loadFrom(env(map[string]string{
		"POOL_SIZE": "100",
		"API_PORT":  "19530",
	}))
	if err == nil {
		t.Fatal("expected a collision error")
	}
	if !strings.Contains(err.Error(), "API_PORT") {
		t.Errorf("error should name API_PORT, got: %v", err)
	}
}

func TestDuplicateListenerPortsAreRejected(t *testing.T) {
	_, err := loadFrom(env(map[string]string{
		"SOCKS_PORT": "9250",
		"HTTP_PORT":  "9250",
	}))
	if err == nil {
		t.Fatal("expected an error when two listeners share a port")
	}
}

func TestBothProxyListenersDisabledIsRejected(t *testing.T) {
	_, err := loadFrom(env(map[string]string{
		"SOCKS_PORT": "",
		"HTTP_PORT":  "",
	}))
	if err == nil {
		t.Fatal("expected an error when every proxy listener is disabled")
	}
}

func TestPortRangeOverflowIsRejected(t *testing.T) {
	_, err := loadFrom(env(map[string]string{
		"INSTANCE_PORT_BASE": "65000",
		"POOL_SIZE":          "200",
	}))
	if err == nil {
		t.Fatal("expected an error when the instance range passes 65535")
	}
	if !strings.Contains(err.Error(), "65535") {
		t.Errorf("error should mention the ceiling, got: %v", err)
	}
}

func TestSessionPortsAreDisabledUnlessAskedFor(t *testing.T) {
	c, err := loadFrom(env(map[string]string{}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Off by default because these listeners take no credentials. A default that
	// opened them would be a default that weakens the pool.
	if c.SessionPortBase != 0 {
		t.Errorf("SessionPortBase = %d by default, want 0", c.SessionPortBase)
	}
}

func TestSessionPortRangeMustNotOverlapTheInstanceBlocks(t *testing.T) {
	// 19000 is INSTANCE_PORT_BASE's default, so this asks for the session block
	// to sit exactly on top of tor's own ports.
	_, err := loadFrom(env(map[string]string{"SESSION_PORT_BASE": "19000"}))
	if err == nil {
		t.Fatal("expected an error when the session range overlaps the instance range")
	}
	if !strings.Contains(err.Error(), "SESSION_PORT_BASE") {
		t.Errorf("error should name the setting at fault, got: %v", err)
	}
}

func TestSessionPortRangeMustNotSwallowAListener(t *testing.T) {
	// A pool of 8 puts the session block at 9248..9255, which covers the default
	// SOCKS_PORT of 9250 — bound twice, and only one of them does what it says.
	_, err := loadFrom(env(map[string]string{
		"SESSION_PORT_BASE": "9248",
		"POOL_SIZE":         "8",
	}))
	if err == nil {
		t.Fatal("expected an error when the session range contains SOCKS_PORT")
	}
}

func TestSessionPortRangeOverflowIsRejected(t *testing.T) {
	_, err := loadFrom(env(map[string]string{
		"SESSION_PORT_BASE": "65500",
		"POOL_SIZE":         "100",
	}))
	if err == nil {
		t.Fatal("expected an error when the session range passes 65535")
	}
	if !strings.Contains(err.Error(), "65535") {
		t.Errorf("error should mention the ceiling, got: %v", err)
	}
}

func TestValidateBoundsChecks(t *testing.T) {
	tests := map[string]func(*Config){
		"pool size zero":       func(c *Config) { c.PoolSize = 0 },
		"pool size too large":  func(c *Config) { c.PoolSize = instancePortBlock + 1 },
		"min ready zero":       func(c *Config) { c.MinReady = 0 },
		"min ready above pool": func(c *Config) { c.MinReady = c.PoolSize + 1 },
		"api port disabled":    func(c *Config) { c.APIPort = 0 },
		"empty data dir":       func(c *Config) { c.DataDir = "" },
		"empty bind host":      func(c *Config) { c.BindHost = "" },
		"session ttl zero":     func(c *Config) { c.SessionTTL = 0 },
		"empty admin user":     func(c *Config) { c.AdminUser = "" },
		"login ttl zero":       func(c *Config) { c.LoginTTL = 0 },
		"negative rate limit":  func(c *Config) { c.LoginRateLimit = -1 },
		"backoff inverted": func(c *Config) {
			c.RemediationBackoff = time.Hour
			c.MaxRemediationBackoff = time.Second
		},
		"history window too short": func(c *Config) {
			c.HistoryResolution = time.Minute
			c.HistoryWindow = time.Second
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := Defaults()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("%s should have been rejected", name)
			}
		})
	}
}
