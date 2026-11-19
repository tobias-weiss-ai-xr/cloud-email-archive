package main

// End-to-end IMAP integration test against the library's in-memory server.
// Verifies the actual sync path: login → select → enumerate UIDs → fetch bodies
// → encrypted blobs in the archive, plus incremental refetch via state.

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

type lit struct{ *bytes.Reader }

func (l lit) Size() int64 { return int64(l.Len()) }

func TestSyncAccountIntegration(t *testing.T) {
	// --- in-process IMAP server ---
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("testuser", "testpw")
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	mem.AddUser(user)

	server := imapserver.New(&imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		InsecureAuth: true,
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {},
			imap.CapIMAP4rev2: {},
		},
	})
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(ln)
	defer server.Close()

	// --- seed two messages ---
	msg1 := []byte("From: a@x.de\r\nSubject: eins\r\n\r\nbody eins\r\n")
	msg2 := []byte("From: b@x.de\r\nSubject: zwei\r\n\r\nbody zwei\r\n")
	if _, err := user.Append("INBOX", lit{bytes.NewReader(msg1)}, &imap.AppendOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := user.Append("INBOX", lit{bytes.NewReader(msg2)}, &imap.AppendOptions{}); err != nil {
		t.Fatal(err)
	}

	// --- cloud-email-archive config pointing at the fake server ---
	dir := t.TempDir()
	id, err := loadKey(writeKeyFor(t))
	if err != nil {
		t.Fatal(err)
	}
	arc := newArchive(dir, id)
	cfg := &Config{
		ArchiveDir: dir,
		StateFile:  dir + "/state.json",
		Accounts: []Account{{
			Name:     "test",
			Host:     "127.0.0.1",
			Port:     ln.Addr().(*net.TCPAddr).Port,
			Security: "none",
			User:     "testuser",
			Password: "testpw",
		}},
	}
	st, err := loadState(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(nopWriter{}, nil))

	// --- first sync ---
	if err := syncAccount(context.Background(), cfg, &cfg.Accounts[0], arc, st, log); err != nil {
		t.Fatal(err)
	}
	blobs, _ := arc.blobs()
	if len(blobs) != 2 {
		t.Fatalf("expected 2 blobs after first sync, got %d", len(blobs))
	}
	// everything decrypted matches the seeded content
	got := map[string]bool{}
	for _, b := range blobs {
		raw, err := arc.get(dir, b.name)
		if err != nil {
			t.Fatal(err)
		}
		got[string(raw)] = true
	}
	if !got[string(msg1)] || !got[string(msg2)] {
		t.Fatalf("decrypted content mismatch: %v", got)
	}

	// --- second sync: nothing new → still 2 blobs ---
	if err := syncAccount(context.Background(), cfg, &cfg.Accounts[0], arc, st, log); err != nil {
		t.Fatal(err)
	}
	if blobs, _ := arc.blobs(); len(blobs) != 2 {
		t.Fatalf("expected still 2 blobs after no-op sync, got %d", len(blobs))
	}

	// --- third sync with one new message → exactly 1 new blob ---
	msg3 := []byte("From: c@x.de\r\nSubject: drei\r\n\r\nbody drei\r\n")
	if _, err := user.Append("INBOX", lit{bytes.NewReader(msg3)}, &imap.AppendOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := syncAccount(context.Background(), cfg, &cfg.Accounts[0], arc, st, log); err != nil {
		t.Fatal(err)
	}
	if blobs, _ := arc.blobs(); len(blobs) != 3 {
		t.Fatalf("expected 3 blobs after incremental sync, got %d", len(blobs))
	}
}

// nopWriter swallows test-server log noise.
type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func writeKeyFor(t *testing.T) string {
	p := t.TempDir() + "/key.txt"
	if err := writeNewKey(p); err != nil {
		t.Fatal(err)
	}
	return p
}

var _ = tls.Config{}
