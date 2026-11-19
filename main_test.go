package main

// CLI dispatch tests for run() — no network, no IMAP server.

import (
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
