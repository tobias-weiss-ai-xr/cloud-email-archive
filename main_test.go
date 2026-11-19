package main

// CLI dispatch tests for run() — no network, no IMAP server.

import (
	"fmt"
	"os"
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
		{name: "version", args: []string{"version"}, wantCode: 0, wantStdout: "cloud-email-archive 0.1.0"},
		{name: "no args shows usage", args: nil, wantCode: 2, wantStdout: "Commands:"},
		{name: "help flag", args: []string{"-h"}, wantCode: 0, wantStdout: "Commands:"},
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
