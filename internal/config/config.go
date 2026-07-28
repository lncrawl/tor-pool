// Package config parses and validates tor-pool's environment-based configuration.
//
// Every knob is an environment variable so the container needs no config file.
// Defaults live here and nowhere else — docs point at this file rather than
// restating values that would silently rot.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SessionSource decides which session key an unauthenticated caller gets.
type SessionSource string

const (
	// SessionFromIP pins each client IP to its own instance.
	SessionFromIP SessionSource = "ip"
	// SessionRandom hands every connection a fresh key, so nothing is sticky.
	SessionRandom SessionSource = "random"
	// SessionShared funnels every anonymous caller onto one shared key.
	SessionShared SessionSource = "shared"
)

// Config is the fully resolved, validated configuration.
type Config struct {
	// Pool
	PoolSize         int
	InstancePortBase int
	SpawnStagger     time.Duration
	MinReady         int
	DataDir          string
	TorBinary        string

	// BootstrapStallTimeout is how long an instance may make no bootstrap
	// progress before it is restarted. Zero disables the check.
	BootstrapStallTimeout time.Duration

	// Listeners. A zero port disables that listener.
	SocksPort int
	HTTPPort  int
	APIPort   int
	BindHost  string

	// Authentication. Every field here is comparable on purpose: Defaults() is
	// compared for equality in tests, so a slice or a map would not compile.
	AdminUser string
	// AdminPassword is generated on first boot when unset, and is the one
	// credential never written to the store — see internal/auth.
	AdminPassword string
	// ProxyToken is an optional statically configured proxy credential, for
	// deployments that provision by environment rather than by dashboard.
	ProxyToken     string
	LoginTTL       time.Duration
	LoginRateLimit int

	// Sessions
	SessionTTL     time.Duration
	DefaultSession SessionSource
	MaxSessions    int
	DrainOnRotate  bool

	// Health and remediation
	FailureWindow         time.Duration
	QuarantineFailures    int
	QuarantineConsecutive int
	EscalationWindow      time.Duration
	RemediationBackoff    time.Duration
	MaxRemediationBackoff time.Duration

	// Tor circuit policy
	ExitNodes           string
	ExcludeExitNodes    string
	StrictNodes         bool
	MaxCircuitDirtiness time.Duration
	ConfluxEnabled      bool
	ExtraTorConfig      string

	// PinExitRelay locks each instance to a single exit relay, so one instance
	// really is one exit IP.
	PinExitRelay bool

	// Observability
	HistoryResolution time.Duration
	HistoryWindow     time.Duration
	LogLevel          string
}

// Defaults returns the configuration used when no environment is set.
func Defaults() Config {
	return Config{
		PoolSize:         5,
		InstancePortBase: 19000,
		SpawnStagger:     500 * time.Millisecond,
		MinReady:         1,
		DataDir:          "/var/lib/tor",
		TorBinary:        "tor",

		// Long enough that a genuinely slow consensus fetch is not cut short,
		// short enough that a stalled instance does not sit out of the pool for
		// the rest of the day. Tor can wedge part-way through bootstrap with a
		// live process, which nothing else notices: the supervisor sees a
		// running tor and the failure ladder never hears from an instance that
		// takes no traffic.
		BootstrapStallTimeout: 3 * time.Minute,

		SocksPort: 9250,
		HTTPPort:  9251,
		APIPort:   8080,
		// Listeners bind 0.0.0.0 *inside* the container on purpose: a
		// container-loopback bind is unreachable through a docker port
		// mapping. Restricting exposure is the host-side publish's job
		// (compose publishes the API as 127.0.0.1:8080:8080).
		BindHost: "0.0.0.0",

		// No password here, and none can be: Defaults() is pure — it is compared
		// for equality in tests and must not reach crypto/rand or the disk. An
		// unset password is therefore never a validation error; internal/auth
		// generates one on first boot and logs it once.
		AdminUser: "admin",
		LoginTTL:  24 * time.Hour,
		// Ten wrong passwords a minute from one address. Generous for a typo,
		// useless for a dictionary.
		LoginRateLimit: 10,

		SessionTTL:     10 * time.Minute,
		DefaultSession: SessionFromIP,
		MaxSessions:    10000,

		// On by default because rotating an instance is a statement that its
		// identity is spent: leaving its callers on it means they keep waiting
		// on the one instance that has just thrown its circuits away. Turn it
		// off when a session's stickiness matters more than its exit — a login
		// that the target site has tied to one IP, say.
		DrainOnRotate: true,

		FailureWindow:         time.Minute,
		QuarantineFailures:    5,
		QuarantineConsecutive: 3,
		EscalationWindow:      5 * time.Minute,
		RemediationBackoff:    30 * time.Second,
		MaxRemediationBackoff: 10 * time.Minute,

		// Tor's own default is 10 minutes, which silently breaks the promise
		// this pool makes: a caller stays pinned to one instance, but that
		// instance would swap exits underneath it every 10 minutes. For a
		// scraper the exit IP *is* the identity, so circuits are reused for
		// much longer and change only on rotation or remediation. The cost is
		// linkability — a longer-lived circuit means more requests share one
		// observable identity, which is the point here but is the opposite of
		// what a privacy-focused client would want.
		MaxCircuitDirtiness: time.Hour,

		// Off, unlike tor's own default. Each conflux set tor pre-builds has its
		// own exit relay and successive streams land on different sets, so an
		// instance served several exit IPs to a caller that never asked to
		// rotate. Multipath throughput is not worth that here.
		ConfluxEnabled: false,

		// Off by default: pinning makes an instance depend on one relay, which
		// is a real trade — a slow or selective exit then affects every request
		// on that instance until the failure ladder moves it. Turn it on when a
		// stable exit IP per instance matters more.
		PinExitRelay: false,

		HistoryResolution: time.Second,
		HistoryWindow:     5 * time.Minute,
		LogLevel:          "info",
	}
}

// InstanceSocksPort returns the loopback SOCKS port for instance index i.
func (c *Config) InstanceSocksPort(i int) int { return c.InstancePortBase + i }

// InstanceControlPort returns the loopback control port for instance index i.
//
// Control ports sit in a second block above the SOCKS block so the two can
// never interleave as the pool grows.
func (c *Config) InstanceControlPort(i int) int {
	return c.InstancePortBase + instancePortBlock + i
}

// instancePortBlock is the gap between the SOCKS and control port blocks. It
// also caps how large a single pool may grow.
const instancePortBlock = 500

// ValidatePoolSize reports whether size is a pool this configuration could
// actually run: the two port blocks have to stay disjoint and fit under 65535.
//
// Exported because the pool can be resized at runtime, and that path needs the
// same answer boot validation gets. Without it, a resize request is free to ask
// for a pool whose ports cannot exist — which spawns thousands of tor processes
// that all fail to bind.
func (c *Config) ValidatePoolSize(size int) error {
	switch {
	case size < 1:
		return fmt.Errorf("pool size must be at least 1, got %d", size)
	case size > instancePortBlock:
		return fmt.Errorf("pool size must be at most %d, got %d", instancePortBlock, size)
	}
	if highest := c.InstanceControlPort(size - 1); highest > 65535 {
		return fmt.Errorf(
			"INSTANCE_PORT_BASE %d with pool size %d needs ports up to %d, past 65535",
			c.InstancePortBase, size, highest)
	}
	return nil
}

// Load reads configuration from the process environment, applying Defaults for
// anything unset, then validates the result.
func Load() (Config, error) {
	return loadFrom(os.LookupEnv)
}

type lookupFunc func(string) (string, bool)

func loadFrom(look lookupFunc) (Config, error) {
	c := Defaults()
	var errs []error

	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	collect(envInt(look, "POOL_SIZE", &c.PoolSize))
	collect(envInt(look, "INSTANCE_PORT_BASE", &c.InstancePortBase))
	collect(envDuration(look, "SPAWN_STAGGER", &c.SpawnStagger))
	collect(envInt(look, "MIN_READY", &c.MinReady))
	collect(envString(look, "DATA_DIR", &c.DataDir))
	collect(envString(look, "TOR_BINARY", &c.TorBinary))
	collect(envDuration(look, "BOOTSTRAP_STALL_TIMEOUT", &c.BootstrapStallTimeout))

	collect(envPort(look, "SOCKS_PORT", &c.SocksPort))
	collect(envPort(look, "HTTP_PORT", &c.HTTPPort))
	collect(envPort(look, "API_PORT", &c.APIPort))
	collect(envString(look, "BIND_HOST", &c.BindHost))

	collect(envString(look, "ADMIN_USER", &c.AdminUser))
	collect(envString(look, "ADMIN_PASSWORD", &c.AdminPassword))
	collect(envString(look, "PROXY_TOKEN", &c.ProxyToken))
	collect(envDuration(look, "LOGIN_TTL", &c.LoginTTL))
	collect(envInt(look, "LOGIN_RATE_LIMIT", &c.LoginRateLimit))

	collect(envDuration(look, "SESSION_TTL", &c.SessionTTL))
	collect(envSessionSource(look, "DEFAULT_SESSION", &c.DefaultSession))
	collect(envInt(look, "MAX_SESSIONS", &c.MaxSessions))
	collect(envBool(look, "DRAIN_ON_ROTATE", &c.DrainOnRotate))

	collect(envDuration(look, "FAILURE_WINDOW", &c.FailureWindow))
	collect(envInt(look, "QUARANTINE_FAILURES", &c.QuarantineFailures))
	collect(envInt(look, "QUARANTINE_CONSECUTIVE", &c.QuarantineConsecutive))
	collect(envDuration(look, "ESCALATION_WINDOW", &c.EscalationWindow))
	collect(envDuration(look, "REMEDIATION_BACKOFF", &c.RemediationBackoff))
	collect(envDuration(look, "MAX_REMEDIATION_BACKOFF", &c.MaxRemediationBackoff))

	collect(envString(look, "TOR_EXIT_NODES", &c.ExitNodes))
	collect(envString(look, "TOR_EXCLUDE_EXIT_NODES", &c.ExcludeExitNodes))
	collect(envBool(look, "TOR_STRICT_NODES", &c.StrictNodes))
	collect(envDuration(look, "TOR_MAX_CIRCUIT_DIRTINESS", &c.MaxCircuitDirtiness))
	collect(envBool(look, "TOR_CONFLUX", &c.ConfluxEnabled))
	collect(envString(look, "TOR_EXTRA_CONFIG", &c.ExtraTorConfig))
	collect(envBool(look, "PIN_EXIT_RELAY", &c.PinExitRelay))

	collect(envDuration(look, "HISTORY_RESOLUTION", &c.HistoryResolution))
	collect(envDuration(look, "HISTORY_WINDOW", &c.HistoryWindow))
	collect(envString(look, "LOG_LEVEL", &c.LogLevel))

	if len(errs) > 0 {
		return c, errors.Join(errs...)
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

// Validate reports every problem it finds at once, so a misconfigured
// container fails fast with a complete message instead of one error per boot.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if c.PoolSize < 1 {
		bad("POOL_SIZE must be at least 1, got %d", c.PoolSize)
	}
	if c.PoolSize > instancePortBlock {
		bad("POOL_SIZE must be at most %d, got %d", instancePortBlock, c.PoolSize)
	}
	if c.MinReady < 1 {
		bad("MIN_READY must be at least 1, got %d", c.MinReady)
	}
	if c.MinReady > c.PoolSize {
		bad("MIN_READY (%d) cannot exceed POOL_SIZE (%d)", c.MinReady, c.PoolSize)
	}
	if c.SpawnStagger < 0 {
		bad("SPAWN_STAGGER cannot be negative")
	}
	if c.BootstrapStallTimeout < 0 {
		bad("BOOTSTRAP_STALL_TIMEOUT cannot be negative (0 disables the check)")
	}
	if c.DataDir == "" {
		bad("DATA_DIR cannot be empty")
	}
	if c.TorBinary == "" {
		bad("TOR_BINARY cannot be empty")
	}
	if c.BindHost == "" {
		bad("BIND_HOST cannot be empty")
	}

	if c.SocksPort == 0 && c.HTTPPort == 0 {
		bad("at least one of SOCKS_PORT or HTTP_PORT must be set")
	}
	if c.APIPort == 0 {
		bad("API_PORT cannot be 0")
	}

	// Deliberately no "ADMIN_USER without ADMIN_PASSWORD" check. It would be
	// right if an unset password meant open access, but it means a generated one,
	// so a custom username with a generated password is a legitimate setup — the
	// name is simply what the first-boot line reports.
	if c.AdminUser == "" {
		bad("ADMIN_USER cannot be empty")
	}
	if c.LoginTTL <= 0 {
		bad("LOGIN_TTL must be positive")
	}
	if c.LoginRateLimit < 0 {
		bad("LOGIN_RATE_LIMIT cannot be negative (0 disables the limit)")
	}

	if c.SessionTTL <= 0 {
		bad("SESSION_TTL must be positive")
	}
	if c.MaxSessions < 1 {
		bad("MAX_SESSIONS must be at least 1, got %d", c.MaxSessions)
	}
	if c.FailureWindow <= 0 {
		bad("FAILURE_WINDOW must be positive")
	}
	if c.QuarantineFailures < 1 {
		bad("QUARANTINE_FAILURES must be at least 1, got %d", c.QuarantineFailures)
	}
	if c.QuarantineConsecutive < 1 {
		bad("QUARANTINE_CONSECUTIVE must be at least 1, got %d", c.QuarantineConsecutive)
	}
	if c.EscalationWindow <= 0 {
		bad("ESCALATION_WINDOW must be positive")
	}
	if c.RemediationBackoff <= 0 {
		bad("REMEDIATION_BACKOFF must be positive")
	}
	if c.MaxRemediationBackoff < c.RemediationBackoff {
		bad("MAX_REMEDIATION_BACKOFF (%s) cannot be shorter than REMEDIATION_BACKOFF (%s)",
			c.MaxRemediationBackoff, c.RemediationBackoff)
	}
	if c.MaxCircuitDirtiness <= 0 {
		bad("TOR_MAX_CIRCUIT_DIRTINESS must be positive")
	}
	if c.HistoryResolution <= 0 {
		bad("HISTORY_RESOLUTION must be positive")
	}
	if c.HistoryWindow < c.HistoryResolution {
		bad("HISTORY_WINDOW (%s) cannot be shorter than HISTORY_RESOLUTION (%s)",
			c.HistoryWindow, c.HistoryResolution)
	}

	if err := c.validatePorts(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// validatePorts guards the one misconfiguration that would otherwise surface as
// a baffling runtime failure: a tor child binding over one of our listeners.
func (c *Config) validatePorts() error {
	var errs []error

	if c.InstancePortBase < 1024 || c.InstancePortBase > 65535 {
		errs = append(errs, fmt.Errorf(
			"INSTANCE_PORT_BASE must be in 1024..65535, got %d", c.InstancePortBase))
		return errors.Join(errs...)
	}

	highest := c.InstanceControlPort(c.PoolSize - 1)
	if highest > 65535 {
		errs = append(errs, fmt.Errorf(
			"INSTANCE_PORT_BASE %d with POOL_SIZE %d needs ports up to %d, past 65535",
			c.InstancePortBase, c.PoolSize, highest))
	}

	listeners := map[int]string{}
	for _, l := range []struct {
		port int
		name string
	}{
		{c.SocksPort, "SOCKS_PORT"},
		{c.HTTPPort, "HTTP_PORT"},
		{c.APIPort, "API_PORT"},
	} {
		if l.port == 0 {
			continue
		}
		if other, dup := listeners[l.port]; dup {
			errs = append(errs, fmt.Errorf("%s and %s are both %d", other, l.name, l.port))
			continue
		}
		listeners[l.port] = l.name
	}

	// Instance ports are allocated from two contiguous blocks; a listener
	// falling inside either one would be bound twice.
	for port, name := range listeners {
		for i := range c.PoolSize {
			if port == c.InstanceSocksPort(i) || port == c.InstanceControlPort(i) {
				errs = append(errs, fmt.Errorf(
					"%s (%d) collides with instance %d's port range starting at INSTANCE_PORT_BASE %d",
					name, port, i, c.InstancePortBase))
				break
			}
		}
	}
	return errors.Join(errs...)
}

func envString(look lookupFunc, key string, dst *string) error {
	if v, ok := look(key); ok {
		*dst = strings.TrimSpace(v)
	}
	return nil
}

func envInt(look lookupFunc, key string, dst *int) error {
	v, ok := look(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s: %q is not a number", key, v)
	}
	*dst = n
	return nil
}

// envPort treats an explicitly empty value as "disable this listener", which is
// how HTTP_PORT="" turns off the HTTP proxy.
func envPort(look lookupFunc, key string, dst *int) error {
	v, ok := look(key)
	if !ok {
		return nil
	}
	if strings.TrimSpace(v) == "" {
		*dst = 0
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s: %q is not a number", key, v)
	}
	if n < 0 || n > 65535 {
		return fmt.Errorf("%s: %d is not a valid port", key, n)
	}
	*dst = n
	return nil
}

func envBool(look lookupFunc, key string, dst *bool) error {
	v, ok := look(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s: %q is not a boolean", key, v)
	}
	*dst = b
	return nil
}

// envDuration accepts Go duration strings ("30s", "5m"). A bare number is
// rejected rather than guessed at, so "60" can never silently mean 60ns.
func envDuration(look lookupFunc, key string, dst *time.Duration) error {
	v, ok := look(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s: %q is not a duration (want e.g. 30s, 5m)", key, v)
	}
	*dst = d
	return nil
}

func envSessionSource(look lookupFunc, key string, dst *SessionSource) error {
	v, ok := look(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	switch s := SessionSource(strings.ToLower(strings.TrimSpace(v))); s {
	case SessionFromIP, SessionRandom, SessionShared:
		*dst = s
		return nil
	default:
		return fmt.Errorf("%s: %q is not one of ip, random, shared", key, v)
	}
}
