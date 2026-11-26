package app

// Config loading and validation tests — including the regression for the
// formerly reachable panic() on empty archive_dir.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigDefaults(t *testing.T) {
	path := writeConfig(t, `
[[accounts]]
name = "faculty"
host = "imap.example.de"
user = "u1"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// paths defaulted (key/state under user config dir, archive in $HOME)
	if cfg.ArchiveDir == "" || cfg.KeyFile == "" || cfg.StateFile == "" {
		t.Fatalf("defaults not filled: %+v", cfg)
	}
	if !strings.Contains(filepath.ToSlash(cfg.KeyFile), "cloud-email-archive") {
		t.Errorf("key_file default should live in cloud-email-archive config dir: %q", cfg.KeyFile)
	}
	a := cfg.Accounts[0]
	if a.Port != 993 {
		t.Errorf("port default = %d, want 993", a.Port)
	}
	if a.Security != "implicit" {
		t.Errorf("security default = %q, want implicit", a.Security)
	}
}

func TestLoadConfigEmptyArchiveDir(t *testing.T) {
	// regression: this used to panic("unreachable")
	path := writeConfig(t, `archive_dir = ""`)
	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("empty archive_dir must be an error, not a panic")
	}
	if !strings.Contains(err.Error(), "archive_dir") {
		t.Errorf("error should mention archive_dir, got: %v", err)
	}
}

func TestLoadConfigEmptyKeyOrState(t *testing.T) {
	for _, field := range []string{"key_file", "state_file"} {
		path := writeConfig(t, field+` = ""`)
		if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("empty %s must fail with a mentioning error", field)
		}
	}
}

func TestLoadConfigInvalidSecurity(t *testing.T) {
	path := writeConfig(t, `
[[accounts]]
name = "a"
host = "h"
user = "u"
security = "telnet"
`)
	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "implicit|starttls|none") {
		t.Fatalf("invalid security must fail, got: %v", err)
	}
}

func TestLoadConfigPortValidation(t *testing.T) {
	for _, port := range []int{-1, 70000} {
		content := fmt.Sprintf(`
[[accounts]]
name = "a"
host = "h"
user = "u"
port = %d
`, port)
		path := writeConfig(t, content)
		if _, err := loadConfig(path); err == nil {
			t.Errorf("port %d must be rejected", port)
		}
	}
	// explicit valid port passes through
	path := writeConfig(t, `
[[accounts]]
name = "a"
host = "h"
user = "u"
port = 143
`)
	if cfg, err := loadConfig(path); err != nil || cfg.Accounts[0].Port != 143 {
		t.Fatalf("port 143 must pass: %v %v", cfg, err)
	}
}

func TestLoadConfigAccountValidation(t *testing.T) {
	cases := []struct {
		toml, wantErr string
	}{
		{"[[accounts]]\nhost=\"h\"\nuser=\"u\"\n", "name is required"},
		{"[[accounts]]\nname=\"a\"\nuser=\"u\"\n", "host is required"},
		{"[[accounts]]\nname=\"a\"\nhost=\"h\"\n", "user is required"},
		{"[[accounts]]\nname=\"  \"\nhost=\"h\"\nuser=\"u\"\n", "name is required"},
	}
	for _, c := range cases {
		path := writeConfig(t, c.toml)
		_, err := loadConfig(path)
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("config %q: want error containing %q, got %v", c.toml, c.wantErr, err)
		}
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := loadConfig(filepath.Join(t.TempDir(), "gone.toml"))
	if err == nil || !strings.Contains(err.Error(), "config.example.toml") {
		t.Fatalf("missing config must error with a hint, got: %v", err)
	}
}

func TestLoadConfigExplicitOverrides(t *testing.T) {
	dir := t.TempDir()
	content := fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n",
		filepath.Join(dir, "archive"), filepath.Join(dir, "key"), filepath.Join(dir, "state"))
	path := writeConfig(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ArchiveDir != filepath.Join(dir, "archive") {
		t.Errorf("archive_dir override lost: %q", cfg.ArchiveDir)
	}
	if cfg.KeyFile != filepath.Join(dir, "key") || cfg.StateFile != filepath.Join(dir, "state") {
		t.Errorf("key/state overrides lost: %q %q", cfg.KeyFile, cfg.StateFile)
	}
}

func TestFindAccount(t *testing.T) {
	cfg := &Config{Accounts: []Account{
		{Name: "Faculty", Host: "h", User: "u"},
		{Name: "verwaltung", Host: "h", User: "u"},
	}}
	// case-insensitive, consistent with wantAccount
	if acc, err := findAccount(cfg, "faculty"); err != nil || acc.Name != "Faculty" {
		t.Errorf("findAccount must be case-insensitive: %v %v", acc, err)
	}
	if acc, err := findAccount(cfg, "VERWALTUNG"); err != nil || acc == nil {
		t.Errorf("findAccount uppercase: %v %v", acc, err)
	}
	if _, err := findAccount(cfg, "nope"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("unknown account must fail naming it, got: %v", err)
	}
	if acc, err := findAccount(cfg, ""); err != nil || acc != nil {
		t.Errorf("empty name must yield nil,nil, got: %v %v", acc, err)
	}
}

func TestLoadConfigRejectsBothPasswordForms(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	content := `
archive_dir = "%s"
key_file = "%s"
state_file = "%s"
[[accounts]]
name = "x"
host = "h"
user = "u"
password = "a"
password_cmd = "echo b"
`
	content = fmt.Sprintf(content,
		filepath.Join(dir, "archive"), filepath.Join(dir, "key.txt"), filepath.Join(dir, "state.json"))
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(cfgPath); err == nil || !strings.Contains(err.Error(), "only one of password") {
		t.Fatalf("want both-set rejection, got %v", err)
	}
}
