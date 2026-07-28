package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// storeFile is the on-disk name inside DATA_DIR. It sits beside the numeric
// per-instance directories; nothing reads that directory, so a non-numeric
// neighbour is harmless.
const storeFile = "auth.json"

// storeVersion is bumped only by a change that an older binary could not read.
const storeVersion = 1

// file is the whole persisted state.
//
// Config is unused today and exists so runtime settings have somewhere to live
// without another schema change.
type file struct {
	Version int    `json:"version"`
	JWTKey  string `json:"jwt_key"`

	// AdminDigest is written only for a password torpool generated itself. An
	// operator-supplied ADMIN_PASSWORD is verified in memory and never stored:
	// a digest of a human-chosen password on disk is a dictionary target, while
	// a digest of 128 random bits is not.
	AdminDigest string `json:"admin_digest,omitempty"`

	Tokens []*Token          `json:"tokens"`
	Config map[string]string `json:"config,omitempty"`
}

// store is the JSON file and the lock that serialises writes to it.
type store struct {
	path string
	// fresh records that the file did not exist, which is what "first boot"
	// means. An empty token list on a file that does exist is a choice.
	fresh bool

	mu   sync.Mutex
	data file
}

// openStore loads the store, creating neither the file nor any credentials.
//
// A parse failure is fatal on purpose. Renaming the file aside and starting over
// would silently regenerate every credential and lock out every consumer, while
// /health kept reporting 200 — the failure mode this project exists to avoid.
func openStore(dir string) (*store, error) {
	// Nothing else creates DATA_DIR itself: tor's supervisor only makes the
	// per-instance subdirectories, and the container image happens to ship the
	// parent. A bind mount or a bare DATA_DIR would otherwise fail here.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory %s: %w", dir, err)
	}

	s := &store{path: filepath.Join(dir, storeFile)}

	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.fresh = true
		s.data = file{Version: storeVersion}
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", s.path, err)
	}

	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf(
			"parse %s: %w — move it aside to start over, which discards every issued token",
			s.path, err)
	}
	if s.data.Version > storeVersion {
		return nil, fmt.Errorf(
			"%s was written by a newer torpool (format %d, this build understands %d)",
			s.path, s.data.Version, storeVersion)
	}
	s.data.Version = storeVersion
	return s, nil
}

// mutate applies fn and persists the result when fn reports a change.
//
// The changed flag is not an optimisation: a boot that needs nothing from the
// store must not require a writable one, so an operator running entirely from
// environment variables is not blocked by a read-only mount.
//
// The lock spans the file write, including its fsyncs. That is safe only because
// nothing on a request path ever takes it: token verification reads the atomic
// index instead (invariant 14). Keep it that way.
func (s *store) mutate(fn func(*file) (changed bool, err error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	changed, err := fn(&s.data)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}

// read gives fn a look at the data under the lock. fn must not retain it.
func (s *store) read(fn func(*file)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
}

func (s *store) saveLocked() error {
	b, err := json.MarshalIndent(&s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode auth store: %w", err)
	}
	if err := atomicWrite(s.path, b); err != nil {
		return fmt.Errorf("save %s: %w", s.path, err)
	}
	return nil
}

// atomicWrite replaces path with b, or leaves the previous contents untouched.
//
// The directory fsync at the end is the step that is easy to skip and expensive
// to omit: without it a power loss can lose the rename itself, leaving the old
// file in place with the new one orphaned.
func atomicWrite(path string, b []byte) error {
	dir := filepath.Dir(path)

	// CreateTemp makes the file 0600, and it lands in the same directory so the
	// rename cannot cross a filesystem boundary.
	tmp, err := os.CreateTemp(dir, ".auth-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	name := tmp.Name()
	// A no-op once the rename succeeds.
	defer func() { _ = os.Remove(name) }()

	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("rename %s: %w", name, err)
	}

	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
