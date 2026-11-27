package app

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// testID creates a fresh age identity in a temp key file (0600 asserted
// elsewhere) and returns the parsed identity.
func testID(t *testing.T) *age.X25519Identity {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "key.txt")
	var id *age.X25519Identity
	var err error
	captureStdout(t, func() {
		err = writeNewKey(keyFile, "")
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err = loadKey(keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestArchiveRoundtrip(t *testing.T) {
	arc := newArchive(t.TempDir(), testID(t))

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

	// decryption roundtrip: every stored blob decrypts to its original bytes
	want := map[string][]byte{}
	for _, b := range blobs {
		got, err := arc.get(b.name)
		if err != nil {
			t.Fatal(err)
		}
		want[b.name] = got
	}
	if _, err := arc.put("faculty", msg1); err != nil {
		t.Fatal(err)
	}
	seen1, seen2 := false, false
	for _, raw := range want {
		if string(raw) == string(msg1) {
			seen1 = true
		}
		if string(raw) == string(msg2) {
			seen2 = true
		}
	}
	if !seen1 || !seen2 {
		t.Fatalf("roundtrip mismatch: neither original message recovered")
	}

	// put after list leaves blob count unchanged (dedup idempotence)
	if blobs2, _ := arc.blobs(); len(blobs2) != 3 {
		t.Fatalf("expected still 3 blobs, got %d", len(blobs2))
	}

	// walk sees all 3, with correct per-account attribution
	perAccount := map[string]int{}
	if err := arc.walk("", func(r msgRef) error {
		perAccount[r.account]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if perAccount["faculty"] != 2 || perAccount["verwaltung"] != 1 {
		t.Fatalf("walk attribution wrong: %v", perAccount)
	}
}

// verify's core guarantee: flipping a single byte of ciphertext must be
// detected (age is authenticated).
func TestArchiveTamperedBlobFailsDetection(t *testing.T) {
	arc := newArchive(t.TempDir(), testID(t))
	if _, err := arc.put("faculty", []byte("From: a@x.de\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	blobs, err := arc.blobs()
	if err != nil || len(blobs) != 1 {
		t.Fatalf("blobs: %v %v", blobs, err)
	}
	raw, err := os.ReadFile(blobs[0].path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF // flip last byte (AEAD tag)
	if err := os.WriteFile(blobs[0].path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := arc.get(blobs[0].name); err == nil {
		t.Fatal("tampered blob must fail decryption")
	}
}

func TestArchiveGetMissingBlob(t *testing.T) {
	arc := newArchive(t.TempDir(), testID(t))
	if _, err := arc.get("nope_0123abcd.age"); err == nil {
		t.Fatal("get on missing blob must fail")
	}
}

func TestAccountOf(t *testing.T) {
	tests := []struct {
		blob, want string
	}{
		{"faculty_abc123.age", "faculty"},
		{"uni_mail_abc123.age", "uni_mail"}, // underscore inside account name
		{"a_b_c_abc123.age", "a_b_c"},
		{"abc123.age", ""},  // no separator
		{"_abc123.age", ""}, // empty account
		{"plain.age", ""},   // no separator at all
	}
	for _, tt := range tests {
		if got := accountOf(tt.blob); got != tt.want {
			t.Errorf("accountOf(%q) = %q, want %q", tt.blob, got, tt.want)
		}
	}
}

func TestBlobName(t *testing.T) {
	a := blobName("faculty", []byte("x"))
	b := blobName("faculty", []byte("x"))
	if a != b {
		t.Fatal("content addressing must be deterministic")
	}
	if blobName("faculty", []byte("x")) == blobName("faculty", []byte("y")) {
		t.Fatal("different content must yield different names")
	}
	if blobName("faculty", []byte("x")) == blobName("other", []byte("x")) {
		t.Fatal("different accounts must yield different names")
	}
	if !strings.HasPrefix(b, "faculty_") || !strings.HasSuffix(b, ".age") {
		t.Fatalf("unexpected blob name %q", b)
	}
}

func TestBlobsFiltering(t *testing.T) {
	dir := t.TempDir()
	arc := newArchive(dir, testID(t))
	if _, err := arc.put("faculty", []byte("m1")); err != nil {
		t.Fatal(err)
	}
	// noise that must be ignored: non-.age file, tmp file, subdirectory
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "faculty_abc.age.tmp123"), []byte("x"), 0o600)
	os.Mkdir(filepath.Join(dir, "subdir"), 0o700)

	blobs, err := arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 1 {
		t.Fatalf("expected 1 blob, got %d: %+v", len(blobs), blobs)
	}
	if !strings.HasSuffix(blobs[0].name, ".age") {
		t.Fatalf("wrong blob kept: %q", blobs[0].name)
	}

	// archive dir missing entirely → no blobs, no error
	empty := newArchive(filepath.Join(t.TempDir(), "does-not-exist"), testID(t))
	if blobs, err := empty.blobs(); err != nil || blobs != nil {
		t.Fatalf("missing dir: blobs=%v err=%v", blobs, err)
	}
}

func TestPutLeavesNoTmpFiles(t *testing.T) {
	dir := t.TempDir()
	arc := newArchive(dir, testID(t))
	for i := 0; i < 3; i++ {
		if _, err := arc.put("faculty", []byte("msg")); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("stale tmp file left behind: %s", e.Name())
		}
	}
}

// walk must skip other accounts' blobs BEFORE decrypting: a corrupted blob of
// an unselected account must not break a filtered walk.
func TestWalkAccountFilterSkipsDecryption(t *testing.T) {
	dir := t.TempDir()
	id := testID(t)
	arc := newArchive(dir, id)
	if _, err := arc.put("faculty", []byte("From: f@x.de\r\n\r\nfaculty body\r\n")); err != nil {
		t.Fatal(err)
	}
	// seed a foreign account's blob, then corrupt it on disk
	if _, err := arc.put("verwaltung", []byte("From: v@x.de\r\n\r\nverwaltung body\r\n")); err != nil {
		t.Fatal(err)
	}
	blobs, _ := arc.blobs()
	for _, b := range blobs {
		if accountOf(b.name) == "verwaltung" {
			raw, _ := os.ReadFile(b.path)
			raw[10] ^= 0xFF
			os.WriteFile(b.path, raw, 0o600)
		}
	}

	var seen []string
	err := arc.walk("faculty", func(r msgRef) error {
		seen = append(seen, r.account)
		return nil
	})
	if err != nil {
		t.Fatalf("filtered walk must not touch the corrupted foreign blob: %v", err)
	}
	if len(seen) != 1 || seen[0] != "faculty" {
		t.Fatalf("walk saw %v, want only faculty", seen)
	}

	// unfiltered walk still detects the corruption
	if err := arc.walk("", func(msgRef) error { return nil }); err == nil {
		t.Fatal("unfiltered walk must surface the corrupted blob")
	}
}

func TestWalkErrorPropagation(t *testing.T) {
	arc := newArchive(t.TempDir(), testID(t))
	for _, m := range []string{"a", "b", "c"} {
		if _, err := arc.put("faculty", []byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := errors.New("stop here")
	err := arc.walk("", func(msgRef) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("walk must propagate callback errors, got %v", err)
	}
}

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name            string
		raw             string
		wantFrom        string
		wantSubject     string
		wantDateYear    int
		wantDateIsEpoch bool
	}{
		{
			name:         "basic CRLF",
			raw:          "From: Max <m@x.de>\r\nSubject: Ein Thema\r\nDate: Mon, 02 Jan 2006 15:04:05 +0100\r\n\r\nbody\r\n",
			wantFrom:     "Max <m@x.de>",
			wantSubject:  "Ein Thema",
			wantDateYear: 2006,
		},
		{
			name:            "folded subject",
			raw:             "From: a@x.de\r\nSubject: first line\r\n continued folded\r\n\r\nbody\r\n",
			wantFrom:        "a@x.de",
			wantSubject:     "first line continued folded",
			wantDateIsEpoch: true, // no Date header -> epoch fallback (TZ-safe: Equal)
		},
		{
			name:            "folded subject with tab",
			raw:             "Subject: one\r\n\ttwo\r\nFrom: a@x.de\r\n\r\n",
			wantSubject:     "one two",
			wantFrom:        "a@x.de",
			wantDateIsEpoch: true,
		},
		{
			name:         "LF-only line endings",
			raw:          "From: a@x.de\nSubject: linux\nDate: Mon, 02 Jan 2006 15:04:05 +0100\n\nbody\n",
			wantFrom:     "a@x.de",
			wantSubject:  "linux",
			wantDateYear: 2006,
		},
		{
			name:            "no header/body separator",
			raw:             "From: a@x.de\r\nSubject: orphan\r\n",
			wantFrom:        "",
			wantSubject:     "",
			wantDateIsEpoch: true,
		},
		{
			name:            "unparsable date falls back to epoch",
			raw:             "From: a@x.de\r\nDate: gestern, irgendwann\r\n\r\nbody\r\n",
			wantFrom:        "a@x.de",
			wantDateIsEpoch: true,
		},
		{
			name:            "first duplicate header wins",
			raw:             "From: first@x.de\r\nFrom: second@x.de\r\nSubject: one\r\nSubject: two\r\n\r\n",
			wantFrom:        "first@x.de",
			wantSubject:     "one",
			wantDateIsEpoch: true,
		},
		{
			name:            "header without colon is ignored",
			raw:             "no-colon-here\r\nFrom: a@x.de\r\n\r\nbody\r\n",
			wantFrom:        "a@x.de",
			wantDateIsEpoch: true,
		},
		{
			name:         "obsolete date format via mail.ParseDate",
			raw:          "From: a@x.de\r\nDate: 02 Jan 06 15:04 -0700\r\n\r\nbody\r\n",
			wantFrom:     "a@x.de",
			wantDateYear: 2006,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			date, from, subject := parseHeaders([]byte(tt.raw))
			if from != tt.wantFrom {
				t.Errorf("from = %q, want %q", from, tt.wantFrom)
			}
			if subject != tt.wantSubject {
				t.Errorf("subject = %q, want %q", subject, tt.wantSubject)
			}
			if tt.wantDateIsEpoch {
				if !date.Equal(time.Unix(0, 0)) {
					t.Errorf("date = %v, want epoch", date)
				}
			} else if date.Year() != tt.wantDateYear {
				t.Errorf("date year = %d, want %d", date.Year(), tt.wantDateYear)
			}
		})
	}
}

func TestKeyPermissions(t *testing.T) {
	needPosixPerms(t)
	keyFile := filepath.Join(t.TempDir(), "k.txt")
	captureStdout(t, func() {
		if err := writeNewKey(keyFile, ""); err != nil {
			t.Fatal(err)
		}
	})
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key perms = %o, want 600", perm)
	}
}

// Passphrase-protected keyfiles: writeNewKey(keyFile, pass) writes age
// armor (disk never holds the secret key), loadKey decrypts it back to the
// same identity; a wrong passphrase fails cleanly, and plaintext keyfiles
// keep loading without any passphrase.
func TestKeyPassphraseRoundTrip(t *testing.T) {
	quietLog()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.txt")
	if err := writeNewKey(keyFile, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), keyArmorMagic) {
		t.Fatalf("passphrase keyfile must be armored, got: %q", raw[:40])
	}
	if strings.Contains(string(raw), "AGE-SECRET-KEY") {
		t.Fatal("armored keyfile must not contain the secret key in the clear")
	}
	id, err := loadKey(keyFile, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := loadKey(keyFile, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if id.Recipient().String() != id2.Recipient().String() {
		t.Fatal("decrypted identities must match")
	}
	// wrong passphrase: clean error, no identity leak
	if _, err := loadKey(keyFile, "wrong"); err == nil {
		t.Fatal("wrong passphrase must fail")
	} else if !strings.Contains(err.Error(), "open key") {
		t.Errorf("wrong-passphrase error should be scoped to opening the key, got: %v", err)
	}
	// no passphrase provided: explicit error (not a prompt hang)
	if _, err := loadKey(keyFile, ""); err == nil {
		t.Fatal("missing passphrase must fail")
	} else if !strings.Contains(err.Error(), "passphrase-protected") {
		t.Errorf("missing-passphrase error should explain the situation, got: %v", err)
	}
	// plaintext keyfile still loads with empty passphrase
	plain := filepath.Join(dir, "plain.txt")
	if err := writeNewKey(plain, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(plain, ""); err != nil {
		t.Fatalf("plaintext keyfile with empty passphrase must load: %v", err)
	}
}

// keygen -passphrase resolves via CEA_PASSPHRASE (non-interactive) and the
// resulting keyfile loads through openArchive's resolution chain.
func TestCmdKeygenPassphraseEnv(t *testing.T) {
	quietLog()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.txt")
	t.Setenv("CEA_PASSPHRASE", "env-pass-42")
	if err := cmdKeygen([]string{"-output", keyFile, "-passphrase"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(keyFile)
	if !strings.HasPrefix(string(raw), keyArmorMagic) {
		t.Fatal("keygen -passphrase must produce an armored keyfile")
	}
	cfg := &Config{ArchiveDir: filepath.Join(dir, "arc"), KeyFile: keyFile}
	if _, err := openArchive(cfg); err != nil { // resolvePassphrase reads CEA_PASSPHRASE
		t.Fatalf("openArchive must resolve the env passphrase: %v", err)
	}
	// wrong env passphrase must fail
	if _, err := loadKey(keyFile, "nope"); err == nil {
		t.Fatal("wrong env passphrase must fail")
	}
}

// passphrase_cmd in the config mirrors the IMAP password_cmd pattern.
func TestResolvePassphraseCmd(t *testing.T) {
	t.Setenv("CEA_PASSPHRASE", "") // isolate from ambient env
	cfg := &Config{PassphraseCmd: "printf 'cmd-pass\nextra'"}
	got, err := resolvePassphrase(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "cmd-pass\nextra" {
		t.Fatalf("resolvePassphrase = %q", got)
	}
	// failing command is a wrapped error, never a fallback to prompt
	cfg.PassphraseCmd = "exit 3"
	if _, err := resolvePassphrase(cfg, false); err == nil {
		t.Fatal("failing passphrase_cmd must fail")
	} else if !strings.Contains(err.Error(), "passphrase_cmd failed") {
		t.Errorf("error should name passphrase_cmd, got: %v", err)
	}
}

func TestLoadKeyErrors(t *testing.T) {
	dir := t.TempDir()

	// missing file
	if _, err := loadKey(filepath.Join(dir, "gone.txt"), ""); err == nil {
		t.Error("missing key file must fail")
	} else if !strings.Contains(err.Error(), "keygen") {
		t.Errorf("error should hint at keygen, got: %v", err)
	}

	// garbage content
	bad := filepath.Join(dir, "bad.txt")
	os.WriteFile(bad, []byte("not a key\n"), 0o600)
	if _, err := loadKey(bad, ""); err == nil {
		t.Error("garbage key must fail")
	}
}

func TestWriteNewKeyOverwrite(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "k.txt")
	var rec1, rec2 *age.X25519Recipient
	captureStdout(t, func() {
		if err := writeNewKey(keyFile, ""); err != nil {
			t.Fatal(err)
		}
	})
	id1, err := loadKey(keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	rec1 = id1.Recipient()
	captureStdout(t, func() {
		if err := writeNewKey(keyFile, ""); err != nil {
			t.Fatal(err)
		}
	})
	id2, err := loadKey(keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	rec2 = id2.Recipient()
	if rec1.String() == rec2.String() {
		t.Fatal("overwritten key must be a fresh identity")
	}
}

// put must fail cleanly (no tmp leftovers) when the archive dir cannot be
// created or written.
func TestPutErrorPaths(t *testing.T) {
	needPosixPerms(t)
	id := testID(t)

	t.Run("dir path is a file", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		arc := newArchive(filepath.Join(blocker, "sub"), id)
		if _, err := arc.put("a", []byte("msg")); err == nil {
			t.Fatal("want MkdirAll error when archive dir parent is a file")
		}
	})
	t.Run("unwritable dir", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o700) }) //nolint:errcheck — allow t.Cleanup to undo
		arc := newArchive(filepath.Join(dir, "arch"), id)
		if _, err := arc.put("a", []byte("msg")); err == nil {
			t.Fatal("want error from read-only dir")
		}
		// no leftover tmp files on the failed write
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.Contains(e.Name(), ".tmp") {
				t.Fatalf("failed put left %s behind", e.Name())
			}
		}
	})
}

func TestSweepStaleTmp(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "a_abc.age.tmp1234")
	fresh := filepath.Join(dir, "b_def.age.tmp5678")
	blob := filepath.Join(dir, "c_ghi.age")
	for _, p := range []string{stale, fresh, blob} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := sweepStaleTmp(dir, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale tmp must be removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("fresh tmp (possible concurrent writer) must be kept")
	}
	if _, err := os.Stat(blob); err != nil {
		t.Error("real blob must be kept")
	}
	if err := sweepStaleTmp(filepath.Join(dir, "does-not-exist"), time.Hour); err != nil {
		t.Errorf("missing dir must be a no-op, got %v", err)
	}
}

// errWriter fails every Write; closeWriter fails only Close. They simulate
// disk-full / I/O errors inside the encryption pipeline.
type errWriter struct{ writeErr, closeErr error }

func (w *errWriter) Write(p []byte) (int, error) { return 0, w.writeErr }
func (w *errWriter) Close() error                { return w.closeErr }

// put must fail cleanly (tmp removed, no partial blob) when the age pipeline
// errors mid-write — exercised via the newWriter test seam.
func TestPutEncryptionErrorPaths(t *testing.T) {
	id := testID(t)
	cases := []struct {
		name string
		w    *errWriter
	}{
		{"encrypt factory fails", nil},
		{"write fails", &errWriter{writeErr: errors.New("disk full")}},
		{"close fails", &errWriter{closeErr: errors.New("flush failed")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			arc := newArchive(dir, id)
			if tc.w == nil {
				arc.newWriter = func(io.Writer, ...age.Recipient) (io.WriteCloser, error) {
					return nil, errors.New("no crypto for you")
				}
			} else {
				w := tc.w
				arc.newWriter = func(io.Writer, ...age.Recipient) (io.WriteCloser, error) {
					return w, nil
				}
			}
			if _, err := arc.put("a", []byte("msg")); err == nil {
				t.Fatal("want error from broken writer seam")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("failed put left %d entries behind, want clean dir", len(entries))
			}
		})
	}
}

// sweep must surface removal failures (e.g. read-only dir).
func TestSweepStaleTmpRemoveError(t *testing.T) {
	needPosixPerms(t)
	dir := t.TempDir()
	stale := filepath.Join(dir, "a_abc.age.tmp1234")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) }) //nolint:errcheck
	if err := sweepStaleTmp(dir, 24*time.Hour); err == nil {
		t.Fatal("want error removing from read-only dir")
	}
}

// writeNewKey must fail cleanly when the target itself is a directory
// (WriteFile error branch).
func TestWriteNewKeyTargetIsDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "key.txt")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	var out string
	out = captureStdout(t, func() {
		if err := writeNewKey(target, ""); err == nil {
			t.Error("want error writing key onto a directory")
		}
	})
	if out != "" {
		t.Errorf("no output expected on failure, got %q", out)
	}
}

// walk must surface archive-dir read errors instead of silently yielding nothing.
func TestWalkBlobsError(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	arc := newArchive(blocker, testID(t))
	called := false
	if err := arc.walk("", func(msgRef) error { called = true; return nil }); err == nil {
		t.Fatal("want error when archive dir is a file")
	}
	if called {
		t.Error("callback must not run")
	}
}

// put must surface unexpected stat errors (unreadable archive dir) instead of
// silently treating the blob as already-present.
func TestPutUnreadableArchiveDir(t *testing.T) {
	needPosixPerms(t)
	quietLog()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	arc := newArchive(dir, id)
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if _, err := arc.put("acc", []byte("mail")); err == nil {
		t.Fatal("put into unreadable dir silently skipped")
	}
}

// sweepStaleTmp must report an unreadable dir rather than pretending it is
// clean (IsNotExist is the only tolerated case).
func TestSweepStaleTmpUnreadable(t *testing.T) {
	needPosixPerms(t)
	quietLog()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if err := sweepStaleTmp(dir, time.Hour); err == nil {
		t.Fatal("sweep on unreadable dir returned nil")
	}
}

// put must surface CreateTemp failures (write-protected dir) instead of
// pretending the blob is archived.
func TestPutWriteProtectedDir(t *testing.T) {
	needPosixPerms(t)
	quietLog()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	arc := newArchive(dir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // r-x: stat ok, create fails
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if _, err := arc.put("acc", []byte("mail")); err == nil {
		t.Fatal("put into write-protected dir silently skipped")
	}
}

// writeNewKey must surface mkdir failures (key path under a file).
func TestWriteNewKeyMkdirError(t *testing.T) {
	quietLog()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeNewKey(filepath.Join(blocker, "key.txt"), ""); err == nil {
		t.Fatal("writeNewKey through file-as-parent succeeded")
	}
}

// put's finalization branches: tmp.Close failure aborts without a partial
// blob. The seam writer's Close closes the underlying tmp first, so put's
// own tmp.Close hits "file already closed".
func TestPutTmpCloseFault(t *testing.T) {
	quietLog()
	env := newTestEnv(t)
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	} // warm-up: archive dir exists
	env.arc.newWriter = func(w io.Writer, r ...age.Recipient) (io.WriteCloser, error) {
		inner, err := age.Encrypt(w, r...)
		if err != nil {
			return nil, err
		}
		return &sideClose{WriteCloser: inner, side: func() {
			w.(*os.File).Close() //nolint:errcheck — the fault
		}}, nil
	}
	if _, err := env.arc.put("acc", []byte("Subject: two\r\n\r\nbeta")); err == nil {
		t.Fatal("tmp.Close failure silently accepted")
	}
	assertBlobCount(t, env.arc, 1) // the warm-up blob, nothing partial
}

// Chmod failure (e.g. tmp vanished before the permission fix on exotic
// filesystems): the writer's Close removes the tmp path; the still-open fd
// makes put's tmp.Close succeed, then Chmod hits ENOENT.
func TestPutChmodFault(t *testing.T) {
	needPosixPerms(t)
	quietLog()
	env := newTestEnv(t)
	env.arc.newWriter = func(w io.Writer, r ...age.Recipient) (io.WriteCloser, error) {
		inner, err := age.Encrypt(w, r...)
		if err != nil {
			return nil, err
		}
		return &sideClose{WriteCloser: inner, side: func() {
			os.Remove(w.(*os.File).Name()) //nolint:errcheck — the fault
		}}, nil
	}
	if _, err := env.arc.put("acc", []byte("Subject: two\r\n\r\nbeta")); err == nil {
		t.Fatal("Chmod failure silently accepted")
	}
	assertBlobCount(t, env.arc, 0)
}

// Rename failure with the tmp file intact (dir permissions flipped under the
// write, e.g. a concurrent admin action on a share): put must surface the
// error and leave no blob — and sweepStaleTmp must clean the orphan tmp up.
func TestPutRenameFault(t *testing.T) {
	needPosixPerms(t)
	quietLog()
	env := newTestEnv(t)
	env.arc.newWriter = func(w io.Writer, r ...age.Recipient) (io.WriteCloser, error) {
		inner, err := age.Encrypt(w, r...)
		if err != nil {
			return nil, err
		}
		return &sideClose{WriteCloser: inner, side: func() {
			os.Chmod(env.arc.dir, 0o500) //nolint:errcheck — r-x: rename blocked
		}}, nil
	}
	mail := []byte("Subject: two\r\n\r\nbeta")
	if _, err := env.arc.put("acc", mail); err == nil {
		t.Fatal("rename failure silently accepted")
	}
	assertBlobCount(t, env.arc, 0)
	os.Chmod(env.arc.dir, 0o700) //nolint:errcheck — restore before cleanup
	// the orphaned tmp is recovered by the crash sweep
	if err := sweepStaleTmp(env.arc.dir, 0); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(env.arc.dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("sweep left orphan tmp file: %s", e.Name())
		}
	}
}

// A dangling-symlink .tmp entry (crashed write + tmp vanished on a share)
// must not break the sweep; the entry itself is simply left alone.
func TestSweepStaleTmpVanishedEntry(t *testing.T) {
	quietLog()
	dir := t.TempDir()
	target := filepath.Join(dir, "gone")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), target); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := os.Rename(target, filepath.Join(dir, "x.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := sweepStaleTmp(dir, time.Hour); err != nil {
		t.Fatalf("vanished entry broke the sweep: %v", err)
	}
}

// sweepStaleTmp must report an entry it cannot delete (dir went r-x after
// listing, e.g. a permissions race on a share) — silent loss would hide a
// growing tmp pile-up.
func TestSweepStaleTmpUndeletable(t *testing.T) {
	needPosixPerms(t)
	quietLog()
	dir := t.TempDir()
	f := filepath.Join(dir, "old.tmp")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(f, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // r-x: listable, not removable
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if err := sweepStaleTmp(dir, time.Hour); err == nil {
		t.Fatal("sweep silently failed to delete stale tmp file")
	}
}

// sideClose runs a fault hook on Close before delegating to the real closer.
type sideClose struct {
	io.WriteCloser
	side func()
}

func (s *sideClose) Close() error {
	err := s.WriteCloser.Close()
	s.side()
	return err
}

// assertBlobCount pins that a failed put left no partial blob behind.
func assertBlobCount(t *testing.T, arc *Archive, want int) {
	t.Helper()
	blobs, err := arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != want {
		t.Fatalf("blobs = %d, want %d (partial write?)", len(blobs), want)
	}
}
