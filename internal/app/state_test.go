package app

// Experiential-memory tests for the fetch-state bookkeeping file.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStateRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	fs := s.folder("faculty", "INBOX")
	fs.UIDValidity = 42
	fs.UIDs = []uint32{3, 1, 2}
	if err := s.save(path); err != nil {
		t.Fatal(err)
	}
	s2, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	f := s2.folder("faculty", "INBOX")
	if f.UIDValidity != 42 {
		t.Fatalf("uidvalidity mismatch: %d", f.UIDValidity)
	}
	// save() sorts UIDs for stable diffs
	if len(f.UIDs) != 3 || f.UIDs[0] != 1 || f.UIDs[2] != 3 {
		t.Fatalf("uids not sorted/saved: %v", f.UIDs)
	}
	// missing state file → empty state, no error
	s3, err := loadState(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s3.Accounts) != 0 {
		t.Fatalf("expected empty state, got %v", s3.Accounts)
	}
}

func TestStateCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := loadState(path); err == nil {
		t.Fatal("corrupt state must fail")
	}
}

// JSON that parses but lacks the accounts map (e.g. `{}`) must not yield a nil map.
func TestStateNilAccountsHealed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte("{}"), 0o600)
	s, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Accounts == nil {
		t.Fatal("Accounts map must be non-nil after load")
	}
	f := s.folder("faculty", "INBOX") // must not panic
	f.UIDs = []uint32{7}
	if err := s.save(path); err != nil {
		t.Fatal(err)
	}
}

func TestStateSaveAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	s.folder("a", "INBOX").UIDValidity = 1
	if err := s.save(path); err != nil {
		t.Fatal(err)
	}
	// atomic write: tmp file consumed by rename, only the real file remains
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("stale tmp file after save: %s", e.Name())
		}
	}
	// file is valid JSON with 0600
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state perms = %o, want 600", info.Mode().Perm())
	}
	var raw map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("state not valid JSON: %v", err)
	}
}

func TestStateFolderAccessorLazy(t *testing.T) {
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	f1 := s.folder("faculty", "INBOX")
	f2 := s.folder("faculty", "INBOX")
	if f1 != f2 {
		t.Fatal("folder() must return the same instance for the same key")
	}
	if _, ok := s.Accounts["faculty"]["INBOX"]; !ok {
		t.Fatal("folder() must register the folder lazily")
	}
}

// A state path that is a directory must surface a read error (not be treated
// as "no state yet").
func TestLoadStatePathIsDir(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadState(dir); err == nil {
		t.Fatal("want error when state path is a directory")
	}
}

// save must fail cleanly when the state file's parent cannot be created.
func TestStateSaveMkdirAllError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &State{Accounts: map[string]map[string]*FolderState{
		"a": {"INBOX": {UIDValidity: 1, UIDs: []uint32{5, 1}}},
	}}
	if err := st.save(filepath.Join(blocker, "sub", "state.json")); err == nil {
		t.Fatal("want error when state parent is a file")
	}
}

// save must fail when the rename target is a directory (file→dir rename fails).
func TestStateSaveRenameError(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	st := &State{Accounts: map[string]map[string]*FolderState{
		"a": {"INBOX": {UIDValidity: 1, UIDs: []uint32{1}}},
	}}
	if err := st.save(statePath); err == nil {
		t.Fatal("want rename error when state path is a directory")
	}
	// no tmp leftover
	if _, err := os.Stat(statePath + ".tmp"); !os.IsNotExist(err) {
		t.Error("failed save left tmp file behind")
	}
}

// JSON with explicit null accounts must re-init the map, not nil-deref later.
func TestLoadStateNullAccounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"accounts": null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Accounts == nil {
		t.Fatal("accounts map must be re-initialized")
	}
}

// save must surface mkdir failures instead of silently losing state updates.
func TestSaveStateMkdirError(t *testing.T) {
	quietLog()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	// parent path component is a regular file → MkdirAll must fail
	if err := s.save(filepath.Join(blocker, "state.json")); err == nil {
		t.Fatal("save through file-as-parent-directory succeeded")
	}
}
