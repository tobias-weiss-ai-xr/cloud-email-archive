package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveRoundtrip(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key.txt")
	if err := writeNewKey(keyFile); err != nil {
		t.Fatal(err)
	}
	id, err := loadKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	arc := newArchive(dir, id)

	msg1 := []byte("From: a@x.de\r\nSubject: Hello\r\n\r\nbody one\r\n")
	msg2 := []byte("From: b@x.de\r\nSubject: Second\r\n\r\nbody two\r\n")

	// first write
	ok, err := arc.put("faculty", msg1)
	if err != nil || !ok {
		t.Fatalf("first put: ok=%v err=%v", ok, err)
	}
	// duplicate content (same raw bytes) must not be written again
	ok, err = arc.put("faculty", msg1)
	if err != nil || ok {
		t.Fatalf("duplicate put should be skipped: ok=%v err=%v", ok, err)
	}
	// different account, same content → different blob
	ok, err = arc.put("verwaltung", msg1)
	if err != nil || !ok {
		t.Fatalf("cross-account put: ok=%v err=%v", ok, err)
	}
	if _, err := arc.put("faculty", msg2); err != nil {
		t.Fatal(err)
	}

	blobs, err := arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 3 {
		t.Fatalf("expected 3 blobs, got %d", len(blobs))
	}

	// decryption roundtrip
	got, err := arc.get(dir, blobs[0].name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg1) && string(got) != string(msg2) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}

	// walk sees all 3
	var seen []string
	if err := arc.walk(func(r msgRef) error {
		seen = append(seen, r.account)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatalf("walk saw %d, want 3", len(seen))
	}
	j := 0
	for _, a := range seen {
		if a == "faculty" {
			j++
		}
	}
	if j != 2 {
		t.Fatalf("expected 2 faculty refs, got %d", j)
	}
}

func TestBlobName(t *testing.T) {
	a := blobName("faculty", []byte("x"))
	b := blobName("faculty", []byte("x"))
	if a != b {
		t.Fatal("content addressing must be deterministic")
	}
	if !strings.HasPrefix(b, "faculty_") || !strings.HasSuffix(b, ".age") {
		t.Fatalf("unexpected blob name %q", b)
	}
	if accountOf(b) != "faculty" {
		t.Fatalf("accountOf(%q) = %q", b, accountOf(b))
	}
}

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

func TestParseHeaders(t *testing.T) {
	raw := []byte("From: Max <m@x.de>\r\nSubject: Ein Thema\r\nDate: Mon, 02 Jan 2006 15:04:05 +0100\r\n\r\nbody\r\n")
	date, from, subj := parseHeaders(raw)
	if from != "Max <m@x.de>" {
		t.Fatalf("from: %q", from)
	}
	if subj != "Ein Thema" {
		t.Fatalf("subject: %q", subj)
	}
	if date.Year() != 2006 {
		t.Fatalf("date: %v", date)
	}
}

func TestKeyPermissions(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "k.txt")
	if err := writeNewKey(keyFile); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key perms = %o, want 600", perm)
	}
}
