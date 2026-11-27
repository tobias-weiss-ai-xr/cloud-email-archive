package app

// Experiential-memory tests for the fetch-state bookkeeping file.

import (
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"testing"
)

func TestStateRoundtrip(t *testing.T) {
	tid := testID(t)

	path := filepath.Join(t.TempDir(), "state.json")
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	fs := s.folder("faculty", "INBOX")
	fs.UIDValidity = 42
	fs.UIDs = []uint32{3, 1, 2}
	if err := s.save(path, tid); err != nil {
		t.Fatal(err)
	}
	s2, err := loadState(path, tid)
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
	s3, err := loadState(filepath.Join(t.TempDir(), "nope.json"), tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(s3.Accounts) != 0 {
		t.Fatalf("expected empty state, got %v", s3.Accounts)
	}
}

func TestStateCorruptJSON(t *testing.T) {
	tid := testID(t)

	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := loadState(path, tid); err == nil {
		t.Fatal("corrupt state must fail")
	}
}

// JSON that parses but lacks the accounts map (e.g. `{}`) must not yield a nil map.
func TestStateNilAccountsHealed(t *testing.T) {
	tid := testID(t)

	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte("{}"), 0o600)
	s, err := loadState(path, tid)
	if err != nil {
		t.Fatal(err)
	}
	if s.Accounts == nil {
		t.Fatal("Accounts map must be non-nil after load")
	}
	f := s.folder("faculty", "INBOX") // must not panic
	f.UIDs = []uint32{7}
	if err := s.save(path, tid); err != nil {
		t.Fatal(err)
	}
}

func TestStateSaveAtomic(t *testing.T) {
	tid := testID(t)

	needPosixPerms(t)
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	s.folder("a", "INBOX").UIDValidity = 1
	if err := s.save(path, tid); err != nil {
		t.Fatal(err)
	}
	// atomic write: tmp file consumed by rename, only the real file remains
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("stale tmp file after save: %s", e.Name())
		}
	}
	// file is age armor (never plaintext JSON) with 0600
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state perms = %o, want 600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), keyArmorMagic) {
		t.Fatal("saved state must be age-armored, not plaintext JSON")
	}
	// and it decrypts back to the same state
	s2, err := loadState(path, tid)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Accounts["a"]["INBOX"].UIDValidity != 1 {
		t.Fatalf("roundtrip lost UIDValidity: %+v", s2.Accounts)
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
	tid := testID(t)

	dir := t.TempDir()
	if _, err := loadState(dir, tid); err == nil {
		t.Fatal("want error when state path is a directory")
	}
}

// save must fail cleanly when the state file's parent cannot be created.
func TestStateSaveMkdirAllError(t *testing.T) {
	tid := testID(t)

	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &State{Accounts: map[string]map[string]*FolderState{
		"a": {"INBOX": {UIDValidity: 1, UIDs: []uint32{5, 1}}},
	}}
	if err := st.save(filepath.Join(blocker, "sub", "state.json"), tid); err == nil {
		t.Fatal("want error when state parent is a file")
	}
}

// save must fail when the rename target is a directory (file→dir rename fails).
func TestStateSaveRenameError(t *testing.T) {
	tid := testID(t)

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	st := &State{Accounts: map[string]map[string]*FolderState{
		"a": {"INBOX": {UIDValidity: 1, UIDs: []uint32{1}}},
	}}
	if err := st.save(statePath, tid); err == nil {
		t.Fatal("want rename error when state path is a directory")
	}
	// no tmp leftover
	if _, err := os.Stat(statePath + ".tmp"); !os.IsNotExist(err) {
		t.Error("failed save left tmp file behind")
	}
}

// JSON with explicit null accounts must re-init the map, not nil-deref later.
func TestLoadStateNullAccounts(t *testing.T) {
	tid := testID(t)

	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"accounts": null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := loadState(path, tid)
	if err != nil {
		t.Fatal(err)
	}
	if st.Accounts == nil {
		t.Fatal("accounts map must be re-initialized")
	}
}

// save must surface mkdir failures instead of silently losing state updates.
func TestSaveStateMkdirError(t *testing.T) {
	tid := testID(t)

	quietLog()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	// parent path component is a regular file → MkdirAll must fail
	if err := s.save(filepath.Join(blocker, "state.json"), tid); err == nil {
		t.Fatal("save through file-as-parent-directory succeeded")
	}
}

// State files written before folder bookkeeping (no "blobs" field) must
// keep loading — the map simply stays nil until the next sync fills it.
func TestStateLegacyWithoutBlobs(t *testing.T) {
	tid := testID(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	legacy := `{"accounts":{"test":{"INBOX":{"uidvalidity":7,"uids":[1,2]}}}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := loadState(path, tid)
	if err != nil {
		t.Fatal(err)
	}
	fs := st.Accounts["test"]["INBOX"]
	if fs.UIDValidity != 7 || len(fs.UIDs) != 2 || fs.Blobs != nil {
		t.Fatalf("legacy state misparsed: %+v", fs)
	}
	if len(st.blobFolders()) != 0 {
		t.Fatal("legacy state must produce an empty blob index")
	}
	// saving must not inject a blobs key for nil maps (stable diff for old versions)
	if err := st.save(path, tid); err != nil {
		t.Fatal(err)
	}
	// the save migrated the plaintext legacy file to age armor
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), keyArmorMagic) {
		t.Fatal("save must migrate plaintext legacy state to armor")
	}
	s2, err := loadState(path, tid)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := jsonOf(s2)["test"]; has {
		// decryptable: check the inner JSON has no blobs key for nil maps
		inner, err := decryptWithIdentity(data, tid)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(inner), "blobs") {
			t.Fatalf("nil Blobs must not be serialized, got:\n%s", inner)
		}
	}
}

// jsonOf is a tiny debugging helper for tests (never used in production).
func jsonOf(s *State) map[string]map[string]*FolderState {
	return s.Accounts
}

// The privacy-critical path: state round-trips encrypted, refuses to write
// plaintext, and a wrong key cannot read folder metadata.
func TestStateEncryptedPrivacy(t *testing.T) {
	tid := testID(t)
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	s.folder("hrz", "Personal/Vertraulich").UIDValidity = 9

	if err := s.save(path, tid); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(raw), keyArmorMagic) {
		t.Fatal("state must be armored on disk")
	}
	if strings.Contains(string(raw), "Personal") || strings.Contains(string(raw), "hrz") {
		t.Fatal("armored state leaked plaintext folder metadata")
	}
	// same key: full roundtrip
	got, err := loadState(path, tid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Accounts["hrz"]["Personal/Vertraulich"].UIDValidity != 9 {
		t.Fatal("roundtrip lost data")
	}
	// wrong key: clean, non-fatal-looking error, no partial data
	if _, err := loadState(path, wrong); err == nil {
		t.Fatal("wrong key must not decrypt state")
	} else if !strings.Contains(err.Error(), "decrypt state") {
		t.Errorf("error should be scoped to the state file, got: %v", err)
	}
	// no key: explicit refusal, not a silent empty state
	if _, err := loadState(path, nil); err == nil {
		t.Fatal("nil key on armored state must fail")
	} else if !strings.Contains(err.Error(), "encrypted but no key") {
		t.Errorf("error should explain the missing key, got: %v", err)
	}
	// save without a key must refuse (no plaintext fallback)
	if err := got.save(path, nil); err == nil {
		t.Fatal("save without key must refuse")
	} else if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("refusal should be explicit, got: %v", err)
	}
	// the refused save must not have corrupted the file
	if _, err := loadState(path, tid); err != nil {
		t.Fatalf("refused save corrupted the state file: %v", err)
	}
}

// A plaintext state still loads WITHOUT any key (legacy + test fixtures),
// and sync migrates it to armor on the next save.
func TestStatePlaintextLoadsKeyless(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	legacy := `{"accounts":{"test":{"INBOX":{"uidvalidity":3,"uids":[5]}}}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := loadState(path, nil) // nil id, plaintext file: fine
	if err != nil {
		t.Fatal(err)
	}
	if st.Accounts["test"]["INBOX"].UIDValidity != 3 {
		t.Fatalf("plaintext load lost data: %+v", st.Accounts)
	}
}
