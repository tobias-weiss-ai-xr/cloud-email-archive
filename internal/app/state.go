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
)

type FolderState struct {
	UIDValidity uint32   `json:"uidvalidity"`
	UIDs        []uint32 `json:"uids"`
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
