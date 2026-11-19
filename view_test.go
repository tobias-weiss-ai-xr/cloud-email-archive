package main

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
