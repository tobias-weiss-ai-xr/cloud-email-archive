package main

// CLI dispatch tests for run() — no network, no IMAP server.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"

	"filippo.io/age"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunDispatch(t *testing.T) {
	env := newTestEnv(t) // valid config so list/verify resolve their deps

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"version"}, wantCode: 0, wantStdout: "cloud-email-archive " + version},
		{name: "no args shows usage", args: nil, wantCode: 2, wantStdout: "Commands:"},
		{name: "help flag", args: []string{"-h"}, wantCode: 0, wantStdout: "Commands:"},
		{name: "help long flag", args: []string{"--help"}, wantCode: 0, wantStdout: "Commands:"},
		{name: "help dash form", args: []string{"-help"}, wantCode: 0, wantStdout: "Commands:"},
		{name: "help command", args: []string{"help"}, wantCode: 0, wantStdout: "Commands:"},
		{name: "unknown command", args: []string{"frobnicate"}, wantCode: 2, wantStderr: "unknown command"},
		{name: "list with missing config", args: []string{"list", "-config", filepath.Join(env.dir, "gone.toml")}, wantCode: 1, wantStderr: "error:"},
		{name: "search without term", args: []string{"search", "-config", env.cfgPath}, wantCode: 1, wantStderr: "search needs a term"},
		{name: "verify healthy archive", args: []string{"verify", "-config", env.cfgPath}, wantCode: 0, wantStdout: "0 ok, 0 failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut string
			var code int
			out = captureStdout(t, func() {
				errOut = captureStream(t, &os.Stderr, func() {
					code = run(tt.args)
				})
			})
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, out, errOut)
			}
			if tt.wantStdout != "" && !strings.Contains(out, tt.wantStdout) {
				t.Errorf("stdout missing %q:\n%s", tt.wantStdout, out)
			}
			if tt.wantStderr != "" && !strings.Contains(errOut, tt.wantStderr) {
				t.Errorf("stderr missing %q:\n%s", tt.wantStderr, errOut)
			}
		})
	}
}

func TestRunKeygen(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "gen-key.txt")
	var out string
	var code int
	out = captureStdout(t, func() { code = run([]string{"keygen", "-output", keyPath}) })
	if code != 0 {
		t.Fatalf("keygen exit %d, output: %s", code, out)
	}
	if !strings.Contains(out, "KEEP THIS KEY SAFE") {
		t.Errorf("keygen must warn about key safety, got: %s", out)
	}
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("generated key missing or wrong perms: %v %v", info, err)
	}
}

// Default paths must live under the user config dir (respects XDG on Linux).
func TestDefaultPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG_CONFIG_HOME is a Linux convention")
	}
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	want := filepath.Join(xdg, "cloud-email-archive")
	if got := defaultConfigPath(); got != filepath.Join(want, "config.toml") {
		t.Errorf("defaultConfigPath = %q, want under %q", got, want)
	}
	if got := defaultKeyPath(); got != filepath.Join(want, "key.txt") {
		t.Errorf("defaultKeyPath = %q", got)
	}
	if got := defaultStatePath(); got != filepath.Join(want, "state.json") {
		t.Errorf("defaultStatePath = %q", got)
	}
}

func TestGetenvDefault(t *testing.T) {
	if got := getenvDefault("CEA_TEST_UNSET", "fallback"); got != "fallback" {
		t.Errorf("unset var: got %q", got)
	}
	t.Setenv("CEA_TEST_SET", "explicit")
	if got := getenvDefault("CEA_TEST_SET", "fallback"); got != "explicit" {
		t.Errorf("set var: got %q", got)
	}
}

// Without HOME and XDG_CONFIG_HOME, userCfgDir falls back to a relative
// "cloud-email-archive" instead of panicking or writing to "/...".
func TestUserCfgDirFallback(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if got := userCfgDir(); got != "cloud-email-archive" {
		t.Errorf("userCfgDir = %q, want relative fallback", got)
	}
}

func TestCmdKeygenErrorPaths(t *testing.T) {
	t.Run("unknown flag", func(t *testing.T) {
		var out string
		out = captureStderr(t, func() {
			if code := run([]string{"keygen", "-bogus"}); code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}
		})
		if !strings.Contains(out, "flag provided but not defined") {
			t.Errorf("stderr = %q", out)
		}
	})
	t.Run("unwritable output dir", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := run([]string{"keygen", "-output", filepath.Join(blocker, "sub", "key.txt")}); code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
	})
}

// loadCfgEnv must surface a bad key file (openArchive branch).
func TestLoadCfgEnvBadKeyFile(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "e2e", msgA)
	body := fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n",
		filepath.Join(env.dir, "archive"), filepath.Join(env.dir, "missing-key.txt"), filepath.Join(env.dir, "state.json"))
	if err := os.WriteFile(env.cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out string
	out = captureStderr(t, func() {
		if code := run([]string{"list", "-config", env.cfgPath}); code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
	})
	if !strings.Contains(out, "read key") {
		t.Errorf("stderr = %q", out)
	}
}

// cmdSync branches: corrupt state, unwritable state dir, no accounts,
// unknown -account.
func TestCmdSyncErrorBranches(t *testing.T) {
	t.Run("corrupt state file", func(t *testing.T) {
		env := newTestEnv(t)
		if err := os.WriteFile(filepath.Join(env.dir, "state.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		// an account is needed so cmdSync reaches loadState at all
		body := fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n\n[[accounts]]\nname = \"a\"\nhost = \"127.0.0.1\"\nport = 1\nsecurity = \"none\"\nuser = \"u\"\npassword = \"p\"\n",
			filepath.Join(env.dir, "archive"), filepath.Join(env.dir, "key.txt"), filepath.Join(env.dir, "state.json"))
		if err := os.WriteFile(env.cfgPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var out string
		out = captureStderr(t, func() {
			if code := run([]string{"sync", "-config", env.cfgPath}); code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}
		})
		if !strings.Contains(out, "parse state") {
			t.Errorf("stderr = %q", out)
		}
	})
	t.Run("no accounts", func(t *testing.T) {
		env := newTestEnv(t)
		var out string
		out = captureStderr(t, func() {
			if code := run([]string{"sync", "-config", env.cfgPath}); code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}
		})
		if !strings.Contains(out, "no accounts configured") {
			t.Errorf("stderr = %q", out)
		}
	})
	t.Run("unknown -account", func(t *testing.T) {
		env := newTestEnv(t)
		env.seed(t, "e2e", msgA)
		body := fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n\n[[accounts]]\nname = \"real\"\nhost = \"127.0.0.1\"\nport = 1\nsecurity = \"none\"\nuser = \"u\"\npassword = \"p\"\n",
			filepath.Join(env.dir, "archive"), filepath.Join(env.dir, "key.txt"), filepath.Join(env.dir, "state.json"))
		if err := os.WriteFile(env.cfgPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var out string
		out = captureStderr(t, func() {
			if code := run([]string{"sync", "-account", "ghost", "-config", env.cfgPath}); code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}
		})
		if !strings.Contains(out, `no account named "ghost"`) {
			t.Errorf("stderr = %q", out)
		}
	})
	t.Run("unwritable state dir joins save error", func(t *testing.T) {
		// account sync succeeds (server unreachable is NOT an error here: use
		// an empty-folder account config) but the state dir is read-only →
		// the save error must fail the run with a "save state" message
		env := newTestEnv(t)
		body := fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n\n[[accounts]]\nname = \"ok\"\nhost = \"127.0.0.1\"\nport = 1\nsecurity = \"none\"\nuser = \"u\"\npassword = \"p\"\nfolders = []\n",
			filepath.Join(env.dir, "archive"), filepath.Join(env.dir, "key.txt"), filepath.Join(env.dir, "statedir", "state.json"))
		if err := os.WriteFile(env.cfgPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		// make the parent of state_file unwritable AFTER mkdirall'd by loadState?
		// no — save() does MkdirAll itself; make the grandparent read-only
		statedir := filepath.Join(env.dir, "statedir")
		if err := os.MkdirAll(statedir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statedir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(statedir, 0o700) }) //nolint:errcheck
		var out string
		out = captureStderr(t, func() {
			if code := run([]string{"sync", "-config", env.cfgPath}); code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}
		})
		if !strings.Contains(out, "save state") {
			t.Errorf("stderr = %q", out)
		}
	})
}

// main() is a one-line os.Exit wrapper — only testable via subprocess
// re-exec. Its single os.Exit statement cannot report in-process coverage
// (os.Exit bypasses both the testing profile writer and go1.20+ GOCOVERDIR
// raw-counter emission — neither has an atexit hook), so it intentionally
// stays at 0% in `go tool cover`; this test proves the wiring instead.
func TestMainSubprocess(t *testing.T) {
	if os.Getenv("CEA_MAIN_CHILD") == "1" {
		main() // exits the process
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainSubprocess$")
	cmd.Env = append(os.Environ(), "CEA_MAIN_CHILD=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("want ExitError, got %v (stderr: %s)", err, stderr.String())
	}
	// child os.Args[1:] = ["-test.run=^TestMainSubprocess$"] -> unknown command -> 2
	if code := exitErr.ExitCode(); code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// flag parse errors surface from loadCfgEnv for every command (list here).
func TestLoadCfgEnvFlagError(t *testing.T) {
	env := newTestEnv(t)
	var out string
	out = captureStderr(t, func() {
		if code := run([]string{"list", "-bogus", "-config", env.cfgPath}); code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
	})
	if !strings.Contains(out, "flag provided but not defined") {
		t.Errorf("stderr = %q", out)
	}
}

// -h prints usage and exits 0 (flag.ErrHelp mapped to success).
func TestFlagErrHelpExitsZero(t *testing.T) {
	for _, args := range [][]string{{"list", "-h"}, {"sync", "-h"}, {"verify", "-h"}} {
		var out string
		out = captureStderr(t, func() {
			if code := run(args); code != 0 {
				t.Errorf("run(%v) = %d, want 0", args, code)
			}
		})
		_ = out
	}
}

// keygen without -output writes to the default path under the user config dir.
func TestCmdKeygenDefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	var out string
	out = captureStdout(t, func() {
		if code := run([]string{"keygen"}); code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})
	key := filepath.Join(home, ".config", "cloud-email-archive", "key.txt")
	if _, err := os.Stat(key); err != nil {
		t.Fatalf("default key not written: %v (out: %q)", err, out)
	}
}

// -account with a resolvable name must take the filtered-account path (and
// still fail the run if the server is unreachable).
func TestCmdSyncAccountFilterResolved(t *testing.T) {
	env := newTestEnv(t)
	body := fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n\n[[accounts]]\nname = \"Real\"\nhost = \"127.0.0.1\"\nport = 1\nsecurity = \"none\"\nuser = \"u\"\npassword = \"p\"\n",
		filepath.Join(env.dir, "archive"), filepath.Join(env.dir, "key.txt"), filepath.Join(env.dir, "state.json"))
	if err := os.WriteFile(env.cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out string
	out = captureStderr(t, func() {
		if code := run([]string{"sync", "-account", "real", "-config", env.cfgPath}); code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
	})
	// case-insensitive resolution must have matched "Real" and taken the
	// filtered-account path (syncAccount's own "Real: dial" prefix shows it ran)
	if !strings.Contains(out, "Real: dial") {
		t.Errorf("stderr = %q", out)
	}
}

func TestLoadConfigErrorPaths(t *testing.T) {
	t.Run("corrupt TOML", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte("this is [not toml"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "parse") {
			t.Fatalf("err = %v, want parse error", err)
		}
	})
	t.Run("path is a directory", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := loadConfig(dir); err == nil {
			t.Fatal("want error when config path is a directory")
		}
	})
}

func TestReadCommandFlagErrors(t *testing.T) {
	env := newTestEnv(t)
	env.seed(t, "e2e", msgA)
	for _, args := range [][]string{
		{"verify", "-bogus", "-config", env.cfgPath},
		{"extract", "-bogus", "-config", env.cfgPath},
	} {
		if code := run(args); code != 1 {
			t.Errorf("run(%v) = %d, want 1", args, code)
		}
	}
}

// loadCfgEnv falls back to CLOUD_EMAIL_ARCHIVE_CONFIG when no -config flag is
// given (default-path env override branch).
func TestLoadCfgEnvEnvVar(t *testing.T) {
	quietLog()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n",
		filepath.Join(dir, "arch"), filepath.Join(dir, "key.txt"), filepath.Join(dir, "state.json"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeNewKey(filepath.Join(dir, "key.txt")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOUD_EMAIL_ARCHIVE_CONFIG", cfgPath)
	env, err := loadCfgEnv(flag.NewFlagSet("list", flag.ContinueOnError), []string{})
	if err != nil {
		t.Fatal(err)
	}
	if env.cfgPath != cfgPath {
		t.Fatalf("env var override ignored: cfgPath = %q", env.cfgPath)
	}
}

// A failing search-index writer must not fail the sync (warn-only contract at
// the sync level, beyond the ensureIndex-level fault test).
func TestSyncIndexFailureWarnsNotFails(t *testing.T) {
	quietLog()
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: one\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)
	cfg, err := loadConfig(env.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// fault only the INDEX write: call 1 is the mail blob itself
	calls := 0
	env.arc.newWriter = func(w io.Writer, r ...age.Recipient) (io.WriteCloser, error) {
		calls++
		if calls > 1 {
			return nil, errors.New("index writer injected")
		}
		return age.Encrypt(w, r...)
	}
	st, err := loadState(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog()); err != nil {
		t.Fatalf("sync failed despite index-only fault: %v", err)
	}
	// the mail itself must still be archived
	blobs, _ := env.arc.blobs()
	if len(blobs) != 1 {
		t.Fatalf("blobs = %d, want 1", len(blobs))
	}
}

// Best-effort steps must not fail the sync: with the archive dir in -wx
// (0333) mode, the sweep's directory listing fails (warn) and the index
// update's blob enumeration fails (warn), while blob WRITES still succeed
// (-wx allows create+rename) — so the sync itself must exit 0 and store mail.
func TestSyncBestEffortStepsWarnNotFail(t *testing.T) {
	quietLog()
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: one\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)
	if err := os.MkdirAll(env.arc.dir, 0o333); err != nil { // -wx: sweep/index read fails, put works
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(env.arc.dir, 0o700) })
	var out string
	captureStdout(t, func() {
		out = captureStderr(t, func() {
			if code := run([]string{"sync", "-config", env.cfgPath}); code != 0 {
				t.Errorf("exit = %d, want 0 (degradation, not failure)", code)
			}
		})
	})
	if !strings.Contains(out, "could not sweep") {
		t.Errorf("sweep warning missing: %q", out)
	}
	if !strings.Contains(out, "index update failed") {
		t.Errorf("index warning missing: %q", out)
	}
	// the mail itself must still be archived
	os.Chmod(env.arc.dir, 0o700) //nolint:errcheck — restore before verifying
	blobs, err := env.arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 1 {
		t.Fatalf("blobs = %d, want 1", len(blobs))
	}
}
