package tor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// FleetOptions configures a Fleet. It mirrors the subset of the process
// configuration that every instance shares.
type FleetOptions struct {
	Size                int
	Binary              string
	DataDir             string
	SocksPortFor        func(index int) int
	ControlPortFor      func(index int) int
	SpawnStagger        time.Duration
	MinReady            int
	ExitNodes           string
	ExcludeExitNodes    string
	StrictNodes         bool
	MaxCircuitDirtiness time.Duration
	ConfluxEnabled      bool
	ExtraTorConfig      string
}

// Fleet supervises a set of tor instances.
//
// It answers "which instances exist and are they usable", and nothing else:
// routing, sessions and health scoring live a layer up. Instances may be added
// and removed while it runs, so callers must never cache the slice returned by
// Instances.
type Fleet struct {
	opts FleetOptions
	log  *slog.Logger

	mu        sync.RWMutex
	instances map[int]*Instance
}

// NewFleet creates an empty fleet. Call Start to bring instances up.
func NewFleet(opts FleetOptions, log *slog.Logger) *Fleet {
	return &Fleet{
		opts:      opts,
		log:       log,
		instances: make(map[int]*Instance, opts.Size),
	}
}

// Start brings up the configured number of instances and returns once MinReady
// of them have bootstrapped.
//
// It deliberately does not wait for all of them: bootstrapping is
// network-bound and largely parallel, so a pool of 10 is usable in about the
// time one instance takes. The rest join as they finish.
func (f *Fleet) Start(ctx context.Context) error {
	ready := make(chan int, f.opts.Size)

	for n := range f.opts.Size {
		if n > 0 && f.opts.SpawnStagger > 0 {
			// Staggering keeps N simultaneous consensus fetches from
			// competing for the same CPU and sockets at boot.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(f.opts.SpawnStagger):
			}
		}
		inst, err := f.Add(ctx, ready)
		if err != nil {
			return err
		}
		f.log.Debug("instance spawned", "instance", inst.Index())
	}

	need := f.opts.MinReady
	if need > f.opts.Size {
		need = f.opts.Size
	}
	for got := 0; got < need; {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %d ready instance(s): %w", need, ctx.Err())
		case idx := <-ready:
			if idx >= 0 {
				got++
				f.log.Info("instance ready", "instance", idx, "ready", got, "need", need)
			}
		}
	}
	return nil
}

// Add creates and starts one more instance, returning as soon as the process is
// launched. Bootstrap completion is reported asynchronously on ready (which may
// be nil); a failed start sends -1.
func (f *Fleet) Add(ctx context.Context, ready chan<- int) (*Instance, error) {
	f.mu.Lock()
	index := f.freeIndexLocked()
	cfg := InstanceConfig{
		Index:               index,
		DataDirectory:       filepath.Join(f.opts.DataDir, strconv.Itoa(index)),
		SocksPort:           f.opts.SocksPortFor(index),
		ControlPort:         f.opts.ControlPortFor(index),
		ExitNodes:           f.opts.ExitNodes,
		ExcludeExitNodes:    f.opts.ExcludeExitNodes,
		StrictNodes:         f.opts.StrictNodes,
		MaxCircuitDirtiness: f.opts.MaxCircuitDirtiness,
		ConfluxEnabled:      f.opts.ConfluxEnabled,
		ExtraConfig:         f.opts.ExtraTorConfig,
	}
	inst := NewInstance(f.opts.Binary, cfg, f.log)
	f.instances[index] = inst
	f.mu.Unlock()

	// Start blocks until bootstrapped, so it runs in the background and the
	// caller learns about readiness through the channel.
	go func() {
		if err := inst.Start(ctx); err != nil {
			if !errors.Is(err, context.Canceled) {
				f.log.Error("instance failed to start", "instance", index, "error", err)
			}
			if ready != nil {
				ready <- -1
			}
			return
		}
		// The exit relay is only knowable once a circuit exists.
		if _, err := inst.RefreshExitNode(); err != nil {
			f.log.Debug("exit node not resolvable yet", "instance", index, "error", err)
		}
		if ready != nil {
			ready <- index
		}
	}()

	return inst, nil
}

// freeIndexLocked returns the lowest index no instance currently holds. Callers
// must hold the lock.
//
// Indexes are reused rather than handed out from an ever-growing counter. Each
// one maps to a fixed pair of ports inside two blocks a fixed distance apart, so
// a counter that only goes up eventually hands an instance a SOCKS port that is
// another instance's control port — after enough resizes, a pool that had always
// been within its configured bounds.
func (f *Fleet) freeIndexLocked() int {
	for index := 0; ; index++ {
		if _, taken := f.instances[index]; !taken {
			return index
		}
	}
}

// Remove stops an instance and drops it from the fleet.
func (f *Fleet) Remove(index int) error {
	f.mu.Lock()
	inst, ok := f.instances[index]
	delete(f.instances, index)
	f.mu.Unlock()

	if !ok {
		return fmt.Errorf("no instance %d", index)
	}
	return inst.Stop()
}

// Instances returns a snapshot of the current instances, ordered by index.
func (f *Fleet) Instances() []*Instance {
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make([]*Instance, 0, len(f.instances))
	for _, inst := range f.instances {
		out = append(out, inst)
	}
	// Stable ordering keeps API responses and dashboard rows from jumping.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Index() > out[j].Index(); j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Get returns one instance by index.
func (f *Fleet) Get(index int) (*Instance, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	inst, ok := f.instances[index]
	return inst, ok
}

// Size reports how many instances exist, ready or not.
func (f *Fleet) Size() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.instances)
}

// ReadyCount reports how many instances have bootstrapped and are routable.
func (f *Fleet) ReadyCount() int {
	var n int
	for _, inst := range f.Instances() {
		if inst.Ready() {
			n++
		}
	}
	return n
}

// Stop shuts every instance down. Instances stop in parallel because each one
// waits out its own SIGTERM grace period.
func (f *Fleet) Stop() error {
	instances := f.Instances()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, inst := range instances {
		wg.Add(1)
		go func(inst *Instance) {
			defer wg.Done()
			if err := inst.Stop(); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(inst)
	}
	wg.Wait()

	f.mu.Lock()
	f.instances = make(map[int]*Instance)
	f.mu.Unlock()

	return errors.Join(errs...)
}
