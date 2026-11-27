package app

// Local fetch-state: which (folder, UID) pairs are already archived, keyed by
// UIDVALIDITY so a mailbox reset triggers a clean re-fetch. Plaintext UIDs only,
// no content — safe to leave in ~/.config (never inside the synced archive dir).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"filippo.io/age"
	"filippo.io/age/armor"
	"strings"
)

type FolderState struct {
	UIDValidity uint32   `json:"uidvalidity"`
	UIDs        []uint32 `json:"uids"`
	// Blobs maps each remembered UID to its archive blob name. Written
	// during sync, so list/extract can attribute a blob to the folder(s)
	// it came from — the blob layer itself is content-addressed and does
	// not know folders. omitempty keeps state files written by older
	// versions loadable here and vice versa.
	Blobs map[uint32]string `json:"blobs,omitempty"`
}

type State struct {
	Accounts map[string]map[string]*FolderState `json:"accounts"` // account → folder → state
}

// loadState reads the fetch-state bookkeeping. The file may be plaintext
// (legacy states, test fixtures) or age-armored to the archive's own
// recipient — armored files need the archive identity, plaintext files load
// with a nil id. Missing file → fresh empty state (id not consulted).
func loadState(path string, id *age.X25519Identity) (*State, error) {
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if bytes.HasPrefix(data, []byte(keyArmorMagic)) {
		if id == nil {
			return nil, fmt.Errorf("state %s is encrypted but no key was provided", path)
		}
		if data, err = decryptWithIdentity(data, id); err != nil {
			return nil, fmt.Errorf("decrypt state %s: %w", path, err)
		}
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.Accounts == nil {
		s.Accounts = map[string]map[string]*FolderState{}
	}
	return s, nil
}

// decryptWithIdentity unwraps age armor addressed to the archive recipient
// (X25519, not scrypt — state loads on every command start, no KDF tax).
func decryptWithIdentity(data []byte, id *age.X25519Identity) ([]byte, error) {
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(data)), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// encryptToIdentity wraps data in age armor for the archive recipient.
func encryptToIdentity(data []byte, id *age.X25519Identity) ([]byte, error) {
	out := &bytes.Buffer{}
	aw := armor.NewWriter(out)
	w, err := age.Encrypt(aw, id.Recipient())
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// blobFolders inverts the per-folder UID→blob maps: blob name → folders
// holding it, sorted (a deduplicated message legitimately lives in several
// folders). Safe on a nil receiver and on states without Blobs entries —
// returns an empty map, callers treat unknown blobs as unfiled.
func (s *State) blobFolders() map[string][]string {
	out := map[string][]string{}
	if s == nil {
		return out
	}
	// collect ALL spellings first: deduping on insert would keep whichever
	// spelling map iteration hits first — non-deterministic. Sort+fold-dedup
	// after the fact keeps the byte-smallest spelling, always the same.
	for _, folders := range s.Accounts {
		for folder, fs := range folders {
			for _, name := range fs.Blobs {
				out[name] = append(out[name], folder)
			}
		}
	}
	for name := range out {
		l := out[name]
		sort.Strings(l)
		deduped := l[:0]
		for i, f := range l {
			if i == 0 || !strings.EqualFold(l[i-1], f) {
				deduped = append(deduped, f)
			}
		}
		out[name] = deduped
	}
	return out
}

func (s *State) account(account string) map[string]*FolderState {
	f, ok := s.Accounts[account]
	if !ok {
		f = map[string]*FolderState{}
		s.Accounts[account] = f
	}
	return f
}

func (s *State) folder(account, folder string) *FolderState {
	f := s.account(account)
	fs, ok := f[folder]
	if !ok {
		fs = &FolderState{}
		f[folder] = fs
	}
	return fs
}

// save persists the state age-encrypted to the archive recipient: the book-
// keeping file (accounts, folder hierarchy, UID→blob attribution) is exactly
// the metadata the privacy model refuses to store in the clear. The JSON is
// encrypted fully in memory, then the armor lands atomically via tmp+rename —
// no plaintext window on disk, and a crashed run cannot leave a half-written
// state behind. Legacy plaintext files migrate automatically: they load
// without a key and the next save writes armored.
func (s *State) save(path string, id *age.X25519Identity) error {
	if id == nil {
		return fmt.Errorf("refusing to write state %s without a key (plaintext state would leak folder metadata)", path)
	}
	for _, folders := range s.Accounts {
		for _, fs := range folders {
			sort.Slice(fs.UIDs, func(i, j int) bool { return fs.UIDs[i] < fs.UIDs[j] })
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err // honest gap: structurally unreachable — fixed-shape struct
	}
	if data, err = encryptToIdentity(data, id); err != nil {
		return fmt.Errorf("encrypt state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) //nolint:errcheck — best effort; don't mask the rename error
		return err
	}
	return nil
}
