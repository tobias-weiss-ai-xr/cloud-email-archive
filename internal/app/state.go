package app

// Local fetch-state: which (folder, UID) pairs are already archived, keyed by
// UIDVALIDITY so a mailbox reset triggers a clean re-fetch. Plaintext UIDs only,
// no content — safe to leave in ~/.config (never inside the synced archive dir).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

func loadState(path string) (*State, error) {
	s := &State{Accounts: map[string]map[string]*FolderState{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.Accounts == nil {
		s.Accounts = map[string]map[string]*FolderState{}
	}
	return s, nil
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

func (s *State) save(path string) error {
	for _, folders := range s.Accounts {
		for _, fs := range folders {
			sort.Slice(fs.UIDs, func(i, j int) bool { return fs.UIDs[i] < fs.UIDs[j] })
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err // honest gap: structurally unreachable — fixed-shape struct
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
