package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errSentinel stands in for whatever a mutation might reject.
var errSentinel = errors.New("refused")

func TestStoreRoundTrips(t *testing.T) {
	dir := t.TempDir()

	first, err := openStore(dir)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	if !first.fresh {
		t.Error("a store with no file should report itself fresh")
	}
	if err := first.mutate(func(f *file) (bool, error) {
		f.JWTKey = "deadbeef"
		f.Tokens = append(f.Tokens, &Token{ID: "abc", Name: "scraper", Scope: ScopeProxy})
		return true, nil
	}); err != nil {
		t.Fatalf("mutate: %v", err)
	}

	second, err := openStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if second.fresh {
		t.Error("a store with a file should not report itself fresh")
	}
	second.read(func(f *file) {
		if f.JWTKey != "deadbeef" {
			t.Errorf("JWTKey = %q, want deadbeef", f.JWTKey)
		}
		if len(f.Tokens) != 1 || f.Tokens[0].Name != "scraper" {
			t.Errorf("Tokens = %+v, want one named scraper", f.Tokens)
		}
		if f.Version != storeVersion {
			t.Errorf("Version = %d, want %d", f.Version, storeVersion)
		}
	})
}

// The file holds signing keys and token digests, so its mode is part of the
// feature rather than hygiene.
func TestStoreFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.mutate(func(f *file) (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, storeFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
}

// Nothing else in the tree creates DATA_DIR — the container image just happens to
// ship it — so a bind mount or a bare DATA_DIR would otherwise fail at boot.
func TestStoreCreatesMissingDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	if _, err := openStore(dir); err != nil {
		t.Fatalf("openStore: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("data directory was not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %04o, want 0700", perm)
	}
}

// A corrupt file must stop the process. Starting over would silently regenerate
// every credential and lock out every consumer while /health still said 200.
func TestStoreRefusesToStartOnACorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, storeFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := openStore(dir)
	if err == nil {
		t.Fatal("expected an error for a corrupt store")
	}
	// The operator has to be able to find the file, and has to be told what
	// moving it aside costs.
	if !strings.Contains(err.Error(), storeFile) {
		t.Errorf("error should name the file, got: %v", err)
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should say what starting over discards, got: %v", err)
	}
}

func TestStoreRefusesAFutureFormat(t *testing.T) {
	dir := t.TempDir()
	b, err := json.Marshal(file{Version: storeVersion + 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, storeFile), b, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := openStore(dir); err == nil {
		t.Fatal("expected an error for a newer store format")
	}
}

// A boot that changes nothing must not need a writable store, so an operator
// running entirely from environment variables is not blocked by a read-only
// mount.
func TestStoreSkipsTheWriteWhenNothingChanged(t *testing.T) {
	dir := t.TempDir()
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.mutate(func(f *file) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, storeFile)); !os.IsNotExist(err) {
		t.Errorf("the file was written for an unchanged mutation (err = %v)", err)
	}
}

// A failing mutation must leave the file alone, not half-written.
func TestStoreLeavesTheFileAloneWhenMutationFails(t *testing.T) {
	dir := t.TempDir()
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.mutate(func(f *file) (bool, error) {
		f.JWTKey = "first"
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	want := errSentinel
	if err := s.mutate(func(f *file) (bool, error) {
		f.JWTKey = "second"
		return true, want
	}); !errors.Is(err, want) {
		t.Errorf("error = %v, want the sentinel back", err)
	}

	reopened, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.read(func(f *file) {
		if f.JWTKey != "first" {
			t.Errorf("JWTKey = %q, want first — a failed mutation was persisted", f.JWTKey)
		}
	})
}

// atomicWrite must replace the file rather than truncate it in place, so a reader
// never sees a partial document.
func TestAtomicWriteLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, storeFile)
	for range 3 {
		if err := atomicWrite(path, []byte(`{"version":1}`)); err != nil {
			t.Fatalf("atomicWrite: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != storeFile {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want just %s", names, storeFile)
	}
}
