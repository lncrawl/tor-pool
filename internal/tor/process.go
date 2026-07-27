package tor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// LogFunc receives a line tor wrote to stderr, already stripped of its
// timestamp prefix.
type LogFunc func(level, message string)

// stopGrace is how long a tor process gets to exit on SIGTERM before it is
// killed. Tor flushes its state directory on shutdown; cutting that short is
// what produces a corrupt DataDirectory on the next start.
const stopGrace = 10 * time.Second

// Process supervises one tor child process.
//
// Its zero value is unusable; construct with NewProcess. All methods are safe
// for concurrent use.
type Process struct {
	cfg    InstanceConfig
	binary string
	onLog  LogFunc

	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan struct{} // closed when the process has been reaped
	exitErr error
}

// NewProcess prepares a supervisor for one instance. Nothing is started until
// Start is called.
func NewProcess(binary string, cfg InstanceConfig, onLog LogFunc) *Process {
	if onLog == nil {
		onLog = func(string, string) {}
	}
	return &Process{binary: binary, cfg: cfg, onLog: onLog}
}

// Config returns the instance configuration this process was built from.
func (p *Process) Config() InstanceConfig { return p.cfg }

// Start writes the torrc and launches tor. It returns as soon as the process is
// running; use WaitForControlPort to find out when it is usable.
func (p *Process) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil {
		return errors.New("tor: process already started")
	}

	if err := os.MkdirAll(p.cfg.DataDirectory, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	// Tor refuses to start if its DataDirectory is group- or world-readable.
	if err := os.Chmod(p.cfg.DataDirectory, 0o700); err != nil {
		return fmt.Errorf("tighten data directory permissions: %w", err)
	}
	if err := os.WriteFile(p.cfg.TorrcPath(), []byte(p.cfg.Torrc()), 0o600); err != nil {
		return fmt.Errorf("write torrc: %w", err)
	}

	// Deliberately not exec.CommandContext: cancelling ctx would SIGKILL tor
	// and skip the graceful shutdown that keeps the DataDirectory intact.
	// Stop() owns termination.
	cmd := exec.Command(p.binary, "-f", p.cfg.TorrcPath()) //nolint:gosec // binary comes from config, not user input
	// A dedicated process group means Stop can signal tor without the signal
	// leaking to torpool itself when it is PID 1.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("pipe stderr: %w", err)
	}
	// Tor logs everything to stderr; stdout stays quiet.
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tor: %w", err)
	}

	p.cmd = cmd
	p.done = make(chan struct{})

	go p.pumpLogs(stderr)
	go p.reap(cmd, p.done)

	return nil
}

// pumpLogs forwards tor's stderr into the event log until the pipe closes.
func (p *Process) pumpLogs(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	// Tor bootstrap lines with a long SUMMARY can exceed the default 64KiB.
	scanner.Buffer(make([]byte, 0, 4096), 256*1024)
	for scanner.Scan() {
		level, msg := splitTorLog(scanner.Text())
		p.onLog(level, msg)
	}
}

// reap waits for the process and records its exit, then signals done. Every
// child must be reaped: torpool is PID 1 and nothing else will.
func (p *Process) reap(cmd *exec.Cmd, done chan struct{}) {
	err := cmd.Wait()
	p.mu.Lock()
	p.exitErr = err
	p.mu.Unlock()
	close(done)
}

// Running reports whether the process is currently alive.
func (p *Process) Running() bool {
	p.mu.Lock()
	done := p.done
	p.mu.Unlock()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

// Pid returns the process id, or 0 if it is not running.
func (p *Process) Pid() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Wait blocks until the process exits and returns its exit error, if any.
func (p *Process) Wait() error {
	p.mu.Lock()
	done := p.done
	p.mu.Unlock()
	if done == nil {
		return errors.New("tor: process was never started")
	}
	<-done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitErr
}

// Stop terminates tor and blocks until it has actually exited.
//
// Callers that go on to delete the DataDirectory MUST wait for this to return:
// removing state under a live tor leaves the next start inheriting a
// half-deleted directory, which fails in ways that look like network problems.
func (p *Process) Stop() error {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	p.mu.Unlock()

	if cmd == nil || done == nil {
		return nil
	}
	select {
	case <-done:
		return nil // already gone
	default:
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("signal tor: %w", err)
	}

	timer := time.NewTimer(stopGrace)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill tor: %w", err)
		}
		<-done
		return nil
	}
}

// splitTorLog turns a tor stderr line into a level and a message. Lines look
// like:
//
//	Jul 27 22:14:03.000 [notice] Bootstrapped 100% (done): Done
//
// Anything unrecognised is reported verbatim at notice level rather than
// dropped.
func splitTorLog(line string) (level, message string) {
	open := strings.IndexByte(line, '[')
	closeIdx := strings.IndexByte(line, ']')
	if open < 0 || closeIdx < open {
		return "notice", strings.TrimSpace(line)
	}
	level = line[open+1 : closeIdx]
	message = strings.TrimSpace(line[closeIdx+1:])
	if message == "" {
		message = strings.TrimSpace(line)
	}
	return level, message
}
