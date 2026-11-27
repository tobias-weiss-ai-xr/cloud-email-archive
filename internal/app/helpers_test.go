package app

// Shared test helpers: stdout/stderr capture and a full test environment
// (config file + key + seeded archive) for CLI-level tests.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// captureStdout runs fn while capturing everything it writes to os.Stdout.
// needPosixPerms skips tests that rely on POSIX file/directory permission
// semantics (chmod 0o500/0o600/0o000 for fault injection or mode
// assertions). Windows maps chmod to an advisory read-only attribute and
// reports different mode bits, so those tests cannot hold there.
func needPosixPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fault injection via POSIX dir permissions is not portable to windows")
	}
}

// skipOnWindows guards tests whose premise is unix-only: POSIX permission
// semantics, HOME-based path resolution, or fault injection that removes an
// open file (Windows refuses deletion of open handles).
func skipOnWindows(t *testing.T, reason string) {
	if runtime.GOOS == "windows" {
		t.Skip(reason)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	return captureStream(t, &os.Stdout, fn)
}

// captureStderr runs fn while capturing everything it writes to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	return captureStream(t, &os.Stderr, fn)
}

func captureStream(t *testing.T, target **os.File, fn func()) string {
	t.Helper()
	orig := *target
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	*target = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	*target = orig
	return <-done
}

type testEnv struct {
	dir     string // base dir
	cfgPath string // config.toml
	arc     *Archive
}

// newTestEnv writes a valid config.toml + key into a temp dir and returns an
// empty archive wired to the same config.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWithConfig(t, "")
}

// newTestEnvWithConfig allows a custom TOML body (paths are filled in
// automatically when the body is empty).
func newTestEnvWithConfig(t *testing.T, body string) *testEnv {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	archiveDir := filepath.Join(dir, "archive")
	statePath := filepath.Join(dir, "state.json")
	cfgPath := filepath.Join(dir, "config.toml")

	captureStdout(t, func() {
		if err := writeNewKey(keyPath, ""); err != nil {
			t.Fatal(err)
		}
	})
	if body == "" {
		body = fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n",
			archiveDir, keyPath, statePath)
	}
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := loadKey(keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{dir: dir, cfgPath: cfgPath, arc: newArchive(archiveDir, id)}
}

// seed puts messages into the archive; raw strings must be full RFC822 mails.
func (e *testEnv) seed(t *testing.T, account string, msgs ...string) []string {
	t.Helper()
	var names []string
	for _, m := range msgs {
		ok, err := e.arc.put(account, []byte(m))
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("seed message not written (duplicate?): %q", m)
		}
		names = append(names, blobName(account, []byte(m)))
	}
	return names
}

// cfg loads the environment's config from disk.
func (e *testEnv) cfg(t *testing.T) *Config {
	t.Helper()
	cfg, err := loadConfig(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// state loads the environment's fetch state from disk.
func (e *testEnv) state(t *testing.T) *State {
	t.Helper()
	cfg := e.cfg(t)
	st, err := loadState(cfg.StateFile, e.arc.id)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

var (
	msgA = "From: Alice <alice@x.de>\r\nSubject: Project Alpha\r\nDate: Mon, 02 Jan 2006 15:04:05 +0100\r\n\r\nalpha body\r\n"
	msgB = "From: Bob <bob@x.de>\r\nSubject: Budget meeting\r\nDate: Tue, 03 Jan 2006 09:30:00 +0100\r\n\r\nbudget numbers\r\n"
	msgC = "From: Carl <carl@x.de>\r\nSubject: Umläute ÄÖÜ\r\nDate: Wed, 04 Jan 2006 12:00:00 +0100\r\n\r\nväry spéciäl\r\n"
)
