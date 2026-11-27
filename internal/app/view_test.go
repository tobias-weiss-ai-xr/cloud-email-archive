package app

// CLI-level tests for the read commands: list, search, extract, verify.
// They run the real cmd* functions against a real encrypted archive on disk
// and assert on the captured stdout/stderr.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCmdList(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "faculty", msgA, msgB)

	var out string
	var err error
	out = captureStdout(t, func() { err = cmdList([]string{"-config", env.cfgPath}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"faculty", "2006-01-02", "Project Alpha", "Alice"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
	if lines := countLines(out); lines != 2 {
		t.Errorf("expected 2 list lines, got %d:\n%s", lines, out)
	}
}

func TestCmdListLimit(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "faculty", msgA, msgB, msgC)

	var out string
	var err error
	out = captureStdout(t, func() { err = cmdList([]string{"-config", env.cfgPath, "-limit", "2"}) })
	if err != nil {
		t.Fatal(err)
	}
	if lines := countLines(out); lines != 2 {
		t.Errorf("-limit 2: expected 2 lines, got %d:\n%s", lines, out)
	}
}

func TestCmdListAccountFilter(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "faculty", msgA)
	env.seed(t, "verwaltung", msgB)

	var out string
	var err error
	out = captureStdout(t, func() { err = cmdList([]string{"-config", env.cfgPath, "-account", "verwaltung"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Budget meeting") || strings.Contains(out, "Project Alpha") {
		t.Errorf("account filter broken, got:\n%s", out)
	}
	// case-insensitive filter must behave the same
	out = captureStdout(t, func() { err = cmdList([]string{"-config", env.cfgPath, "-account", "VERWALTUNG"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Budget meeting") {
		t.Errorf("case-insensitive account filter broken, got:\n%s", out)
	}
}

func TestCmdListMultibyteTruncation(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "faculty", msgC) // subject with umlauts

	var out string
	var err error
	out = captureStdout(t, func() { err = cmdList([]string{"-config", env.cfgPath}) })
	if err != nil {
		t.Fatal(err)
	}
	if !validUTF8Lines(out) {
		t.Errorf("list produced invalid UTF-8 (rune-splitting bug):\n%q", out)
	}
	if !strings.Contains(out, "Umläute") {
		t.Errorf("multibyte subject mangled:\n%s", out)
	}
}

func TestCmdSearch(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "faculty", msgA, msgB)

	var out string
	var err error
	out = captureStdout(t, func() { err = cmdSearch([]string{"-config", env.cfgPath, "budget"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Budget meeting") || strings.Contains(out, "Project Alpha") {
		t.Errorf("search wrong matches:\n%s", out)
	}
	if !strings.Contains(out, "1 match(es)") {
		t.Errorf("match count missing:\n%s", out)
	}
	// body terms match too, case-insensitively
	out = captureStdout(t, func() { err = cmdSearch([]string{"-config", env.cfgPath, "NUMBERS"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1 match(es)") {
		t.Errorf("case-insensitive body search broken:\n%s", out)
	}
	// no hits
	out = captureStdout(t, func() { err = cmdSearch([]string{"-config", env.cfgPath, "zzz-nothing"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "0 match(es)") {
		t.Errorf("zero-hit search broken:\n%s", out)
	}
}

func TestCmdSearchNeedsTerm(t *testing.T) {
	env := newTestEnv(t)
	if err := cmdSearch([]string{"-config", env.cfgPath}); err == nil {
		t.Fatal("search without term must fail")
	}
}

func TestSafeFolder(t *testing.T) {
	cases := map[string]string{
		"INBOX":        "INBOX",
		"Archive/2023": filepath.Join("Archive", "2023"),
		"":             "", // unfiled sentinel stays empty
		"..":           "_",
		"../evil":      filepath.Join("_", "evil"),
		"a:b":          "a_b",
		"nul?":         "nul_",
		"trailing.":    "trailing",
		"trail space ": "trail space",
		".hidden":      ".hidden", // dotfiles are legal dirs here
		"a\x01b":       "a_b",
		"über/Ärzte":   filepath.Join("über", "Ärzte"), // unicode survives
	}
	for in, want := range cases {
		if got := safeFolder(in); got != want {
			t.Errorf("safeFolder(%q) = %q, want %q", in, got, want)
		}
	}
	// no component may ever escape the output dir, whatever the input:
	// no "." or ".." component, never an absolute path
	for _, evil := range []string{"../../..", "..\\..\\win", "a/../..", "/abs", "C:\\x", "./x"} {
		got := safeFolder(evil)
		if filepath.IsAbs(got) {
			t.Errorf("safeFolder(%q) = %q: absolute", evil, got)
		}
		for _, part := range strings.Split(got, string(filepath.Separator)) {
			if part == "." || part == ".." {
				t.Errorf("safeFolder(%q) = %q: traversal component", evil, got)
			}
		}
	}
}

// list shows the folder column from state; unattributed blobs show "-".
func TestCmdListFolderColumn(t *testing.T) {
	env, _, _ := expireFixture(t)
	out := captureStdout(t, func() {
		if err := cmdList([]string{"-config", env.cfgPath}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, " INBOX ") {
		t.Fatalf("list must show the folder column, got:\n%s", out)
	}
	// drop the attribution → folder shows as "-"
	st := env.state(t)
	fs := st.Accounts["test"]["INBOX"]
	fs.Blobs = nil
	if err := st.save(env.cfg(t).StateFile, env.arc.id); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		if err := cmdList([]string{"-config", env.cfgPath}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, " - ") {
		t.Fatalf("unattributed blobs must show \"-\", got:\n%s", out)
	}
	// an unreadable state file must not break list — only the column
	if err := os.WriteFile(env.cfg(t).StateFile, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		if err := cmdList([]string{"-config", env.cfgPath}); err != nil {
			t.Fatalf("unreadable state must degrade, not fail: %v", err)
		}
	})
	if !strings.Contains(out, " - ") {
		t.Fatalf("broken state must cost only the folder column, got:\n%s", out)
	}
}

// a blob attributed to several folders lists both; EqualFold folders
// (case-differing server names) must not duplicate the entry.
func TestFolderLabelMultiFolder(t *testing.T) {
	st := &State{Accounts: map[string]map[string]*FolderState{
		"test": {
			"Sent":       &FolderState{Blobs: map[uint32]string{1: "test-abc.age"}},
			"sent/items": &FolderState{Blobs: map[uint32]string{1: "test-abc.age"}},
			"SENT":       &FolderState{Blobs: map[uint32]string{1: "test-abc.age"}},
		},
	}}
	idx := st.blobFolders()
	// "SENT" folds onto "Sent" — one entry, deterministically the
	// byte-smallest spelling survives map iteration order
	if got := folderLabel(idx, "test-abc.age"); got != "SENT,sent/items" {
		t.Fatalf("folderLabel = %q, want \"SENT,sent/items\"", got)
	}
	if folderLabel(idx, "gone.age") != "-" {
		t.Fatal("unknown blob must show -")
	}
}

func TestCmdExtract(t *testing.T) {
	env := newTestEnv(t)
	names := env.seed(t, "faculty", msgA)
	env.seed(t, "verwaltung", msgB)
	outDir := filepath.Join(env.dir, "eml-out")

	var out string
	var err error
	out = captureStdout(t, func() {
		err = cmdExtract([]string{"-config", env.cfgPath, "-dir", outDir})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "wrote 2 message(s)") {
		t.Errorf("extract summary wrong: %s", out)
	}
	// faculty file exists with original content
	eml := filepath.Join(outDir, "faculty", strings.TrimSuffix(names[0], ".age")+".eml")
	data, err := os.ReadFile(eml)
	if err != nil {
		t.Fatalf("extracted file missing: %v", err)
	}
	if string(data) != msgA {
		t.Errorf("extracted content mismatch:\n%q", data)
	}
	// without -account, the second account is extracted too
	veml := filepath.Join(outDir, "verwaltung", strings.TrimSuffix(blobName("verwaltung", []byte(msgB)), ".age")+".eml")
	if vdata, err := os.ReadFile(veml); err != nil || string(vdata) != msgB {
		t.Errorf("second account not extracted: %v", err)
	}
}

func TestCmdExtractAccountFilterAndNoDir(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "faculty", msgA)
	env.seed(t, "verwaltung", msgB)
	outDir := filepath.Join(env.dir, "eml-out2")

	var out string
	var err error
	out = captureStdout(t, func() {
		err = cmdExtract([]string{"-config", env.cfgPath, "-dir", outDir, "-account", "faculty"})
	})
	_ = out
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "verwaltung")); !os.IsNotExist(err) {
		t.Error("-account filter leaked into extract output")
	}

	// missing -dir must fail
	if err := cmdExtract([]string{"-config", env.cfgPath}); err == nil {
		t.Fatal("extract without -dir must fail")
	}
}

func TestCmdVerify(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "faculty", msgA, msgB)

	var out string
	var err error
	out = captureStdout(t, func() { err = cmdVerify([]string{"-config", env.cfgPath}) })
	if err != nil {
		t.Fatalf("verify on healthy archive failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "2 ok, 0 failed, 0 skipped") {
		t.Errorf("verify summary wrong: %s", out)
	}
}

func TestCmdVerifyDetectsCorruption(t *testing.T) {
	env := newTestEnv(t)
	names := env.seed(t, "faculty", msgA, msgB)

	// corrupt one blob beyond repair
	raw, err := os.ReadFile(filepath.Join(env.arc.dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF
	if err := os.WriteFile(filepath.Join(env.arc.dir, names[0]), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut string
	var cmdErr error
	out = captureStdout(t, func() {
		errOut = captureStream(t, &os.Stderr, func() {
			cmdErr = cmdVerify([]string{"-config", env.cfgPath})
		})
	})
	if cmdErr == nil {
		t.Fatalf("verify must fail on corruption\nstdout: %s\nstderr: %s", out, errOut)
	}
	if !strings.Contains(out, "1 ok, 1 failed") {
		t.Errorf("verify summary wrong:\nstdout: %s", out)
	}
	if !strings.Contains(errOut, "FAIL") {
		t.Errorf("verify must print FAIL for the broken blob:\nstderr: %s", errOut)
	}
}

func TestCmdVerifyAccountSkip(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "faculty", msgA)
	env.seed(t, "other_account", msgB) // underscore account name

	var out string
	var err error
	out = captureStdout(t, func() { err = cmdVerify([]string{"-config", env.cfgPath, "-account", "faculty"}) })
	if err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "1 ok, 0 failed, 1 skipped") {
		t.Errorf("verify skip accounting wrong: %s", out)
	}
}

// --- small assertion helpers ---

func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func validUTF8Lines(s string) bool {
	return utf8.ValidString(s)
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"eleven chars", 10, "eleven ch…"},
		{"", 5, ""},
		{"anything", 0, ""},            // n <= 0 → empty, never panics
		{"anything", -3, ""},           //nolint:staticcheck
		{"äöü äöü äöü", 8, "äöü äöü…"}, // rune-safe: umlauts are 1 column
	}
	for _, tt := range tests {
		got := truncate(tt.in, tt.n)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
		}
		// invariant: result is always valid UTF-8
		if !utf8.ValidString(got) {
			t.Errorf("truncate produced invalid UTF-8: %q", got)
		}
	}
}

// verify must catch a blob whose filename no longer matches the SHA-256 of
// its content (renames, copy bugs, provider mangling) — the core
// "verifiable archive" guarantee beyond mere decryptability.
func TestCmdVerifyHashMismatch(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "e2e", msgA)

	blobs, _ := env.arc.blobs()
	if len(blobs) != 1 {
		t.Fatalf("want 1 blob, got %d", len(blobs))
	}
	tampered := filepath.Join(env.dir, "archive", "e2e_deadbeef00000000000000000000000000000000000000000000000000000000.age")
	if err := os.Rename(blobs[0].path, tampered); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr string
	stdout = captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if code := run([]string{"verify", "-config", env.cfgPath}); code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}
		})
	})
	// FAIL lines go to stderr, the summary to stdout
	if !strings.Contains(stderr, "hash mismatch") {
		t.Fatalf("stderr missing hash mismatch: %q", stderr)
	}
	if !strings.Contains(stdout, "0 ok, 1 failed") {
		t.Fatalf("stdout summary wrong: %q", stdout)
	}
}

// searching an archive containing a corrupt blob must surface the error, not
// silently skip the message.
func TestCmdSearchCorruptBlob(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "e2e", msgA, msgB)

	blobs, _ := env.arc.blobs()
	data, _ := os.ReadFile(blobs[0].path)
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(blobs[0].path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// flags must precede the positional term (Go flag parsing stops there)
	if code := run([]string{"search", "-config", env.cfgPath, "alpha"}); code != 1 {
		t.Fatalf("exit = %d, want 1 (corrupt blob must fail search)", code)
	}
}

// extract into a path whose parent is a file must fail with a usable error.
func TestCmdExtractMkdirAllError(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "e2e", msgA)

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"extract", "-dir", filepath.Join(blocker, "out"), "-config", env.cfgPath}); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}

// archive dir being a regular file must produce a clean error, not a panic
// (regression: blobs() used to ignore the Info() error, risking a nil deref).
func TestCmdVerifyArchiveDirIsFile(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "e2e", msgA)

	blocker := filepath.Join(env.dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n",
		blocker, filepath.Join(env.dir, "key.txt"), filepath.Join(env.dir, "state.json"))
	if err := os.WriteFile(env.cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := run([]string{"verify", "-config", env.cfgPath}); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}

// extract must fail when an .eml target exists as a directory (e.g. a
// collided sync dir) instead of silently skipping.
func TestCmdExtractWriteFileError(t *testing.T) {
	env := newTestEnv(t)
	names := env.seed(t, "e2e", msgA)
	outDir := filepath.Join(t.TempDir(), "out")
	// .eml target = blob filename minus .age, plus .eml
	collision := filepath.Join(outDir, "e2e", strings.TrimSuffix(names[0], ".age")+".eml")
	if err := os.MkdirAll(collision, 0o700); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"extract", "-dir", outDir, "-config", env.cfgPath}); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}

// A second index run must report "up to date" instead of implying a rebuild.
func TestCmdIndexUpToDate(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := cmdIndex([]string{"-config", env.cfgPath}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "up to date") {
		t.Fatalf("want up-to-date report, got %q", out)
	}
	// after a new blob it must report coverage again
	if _, err := env.arc.put("acc", []byte("Subject: two\r\n\r\nbeta")); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		if err := cmdIndex([]string{"-config", env.cfgPath}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "2 blob(s) covered") {
		t.Fatalf("want coverage report, got %q", out)
	}
}

// A term shorter than 3 characters explains why the raw scan runs.
func TestCmdSearchShortTermHint(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha beta")); err != nil {
		t.Fatal(err)
	}
	// a second blob that does NOT match: exercises the raw-scan skip branch
	if _, err := env.arc.put("acc", []byte("Subject: two\r\n\r\nunrelated text")); err != nil {
		t.Fatal(err)
	}
	errOut := captureStderr(t, func() {
		out := captureStdout(t, func() {
			if err := cmdSearch([]string{"-config", env.cfgPath, "ha"}); err != nil {
				t.Fatal(err)
			}
		})
		if !strings.Contains(out, "1 match(es)") {
			t.Fatalf("raw scan result wrong (want exactly the matching blob): %q", out)
		}
	})
	if !strings.Contains(errOut, "shorter than 3 characters") { // "ha" matches "alpha"
		t.Fatalf("want short-term hint on stderr, got %q", errOut)
	}
}

// list on an empty archive must not print nothing at all.
func TestCmdListEmptyArchiveHint(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	out := captureStdout(t, func() {
		if err := cmdList([]string{"-config", env.cfgPath}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "(no messages in archive)") {
		t.Fatalf("want empty-archive hint, got %q", out)
	}
}

// Fresh install (archive dir not yet created): index/list/search must degrade
// gracefully instead of surfacing raw "no such file" errors.
func TestFreshArchiveDirDegradation(t *testing.T) {
	env := newTestEnvWithConfig(t, "")
	os.RemoveAll(filepath.Join(env.dir, "archive")) // config exists, dir does not
	out := captureStdout(t, func() {
		if err := cmdIndex([]string{"-config", env.cfgPath}); err != nil {
			t.Fatalf("index on fresh install failed: %v", err)
		}
	})
	if !strings.Contains(out, "0 blob(s) covered, 0 segment(s)") {
		t.Fatalf("index: %q", out)
	}
	out = captureStdout(t, func() {
		if err := cmdList([]string{"-config", env.cfgPath}); err != nil {
			t.Fatalf("list on fresh install failed: %v", err)
		}
	})
	if !strings.Contains(out, "(no messages in archive)") {
		t.Fatalf("list: %q", out)
	}
	errOut := captureStderr(t, func() {
		out := captureStdout(t, func() {
			if err := cmdSearch([]string{"-config", env.cfgPath, "anything"}); err != nil {
				t.Fatalf("search on fresh install failed: %v", err)
			}
		})
		if !strings.Contains(out, "0 match(es)") {
			t.Fatalf("search: %q", out)
		}
	})
	if strings.Contains(errOut, "no such file") {
		t.Fatalf("search must fall back quietly on fresh install, stderr: %q", errOut)
	}
}

// corrupt blob must fail list and extract (walk propagates decrypt errors).
func TestCmdListCorruptBlob(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	b, err := env.arc.blobs()
	if err != nil || len(b) != 1 {
		t.Fatalf("blobs: %v (%v)", b, err)
	}
	os.WriteFile(b[0].path, []byte("garbage"), 0o600)
	if err := cmdList([]string{"-config", env.cfgPath}); err == nil {
		t.Fatal("list silently ignored corrupt blob")
	}
}

func TestCmdExtractCorruptBlob(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	b, err := env.arc.blobs()
	if err != nil || len(b) != 1 {
		t.Fatalf("blobs: %v (%v)", b, err)
	}
	os.WriteFile(b[0].path, []byte("garbage"), 0o600)
	out := t.TempDir()
	if err := cmdExtract([]string{"-config", env.cfgPath, "-dir", out}); err == nil {
		t.Fatal("extract silently ignored corrupt blob")
	}
}

// index must fail loudly when blobs are unreadable (coverage probe path).
func TestCmdIndexBlobsError(t *testing.T) {
	needPosixPerms(t)
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(env.arc.dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(env.arc.dir, 0o700) })
	if err := cmdIndex([]string{"-config", env.cfgPath}); err == nil {
		t.Fatal("index ignored unreadable archive dir")
	}
}

// index/extract without a usable config must fail with the config error
// (loadCfgEnv arg-error plumbing for these commands).
func TestCmdIndexExtractListNeedConfig(t *testing.T) {
	quietLog()
	t.Setenv("CLOUD_EMAIL_ARCHIVE_CONFIG", "")
	if err := cmdIndex([]string{}); err == nil {
		t.Fatal("index without config succeeded")
	}
	if err := cmdExtract([]string{}); err == nil {
		t.Fatal("extract without config succeeded")
	}
	if err := cmdList([]string{}); err == nil {
		t.Fatal("list without config succeeded")
	}
	if err := cmdSearch([]string{}); err == nil {
		t.Fatal("search without config succeeded")
	}
}
