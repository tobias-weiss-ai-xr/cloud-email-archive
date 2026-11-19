package main

// Configuration for cloud-email-archive. Accounts is a generic list (0..n), so each account
// type — faculty dovecot, Verwaltung Exchange, whatever — is optional and any
// combination is supported.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	ArchiveDir string    `toml:"archive_dir"`
	KeyFile    string    `toml:"key_file"`
	StateFile  string    `toml:"state_file"`
	Accounts   []Account `toml:"accounts"`
}

type Account struct {
	Name        string   `toml:"name"` // e.g. "faculty" or "verwaltung"
	Host        string   `toml:"host"`
	Port        int      `toml:"port"`
	Security    string   `toml:"security"` // "implicit" (default), "starttls", "none"
	User        string   `toml:"user"`
	Password    string   `toml:"password"`
	PasswordCmd string   `toml:"password_cmd"`
	Folders     []string `toml:"folders"` // ["*"] = all selectable folders (default)
}

func defaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		ArchiveDir: filepath.Join(home, "cloud-email-archive"),
		KeyFile:    defaultKeyPath(),
		StateFile:  defaultStatePath(),
	}
}

// loadConfig reads the TOML file and fills unset fields with sane defaults.
// Missing file → defaults with no accounts (so `keygen` works before config exists).
func loadConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := toml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	case os.IsNotExist(err):
		return nil, fmt.Errorf("config not found: %s (see README; copy config.example.toml)", path)
	default:
		return nil, err
	}
	if cfg.ArchiveDir == "" {
		return nil, fmt.Errorf("config %s: archive_dir must not be empty", path)
	}
	if cfg.KeyFile == "" {
		return nil, fmt.Errorf("config %s: key_file must not be empty", path)
	}
	if cfg.StateFile == "" {
		return nil, fmt.Errorf("config %s: state_file must not be empty", path)
	}
	for i := range cfg.Accounts {
		a := &cfg.Accounts[i]
		a.Name = strings.TrimSpace(a.Name)
		a.Host = strings.TrimSpace(a.Host)
		a.User = strings.TrimSpace(a.User)
		if a.Name == "" {
			return nil, fmt.Errorf("config %s: account[%d]: name is required", path, i)
		}
		if a.Host == "" {
			return nil, fmt.Errorf("config %s: account %q: host is required", path, a.Name)
		}
		if a.User == "" {
			return nil, fmt.Errorf("config %s: account %q: user is required", path, a.Name)
		}
		if a.Password != "" && a.PasswordCmd != "" {
			return nil, fmt.Errorf("config %s: account %q: set only one of password / password_cmd", path, a.Name)
		}
		if a.Port == 0 {
			a.Port = 993
		}
		if a.Port < 1 || a.Port > 65535 {
			return nil, fmt.Errorf("config %s: account %q: invalid port %d", path, a.Name, a.Port)
		}
		switch a.Security {
		case "", "implicit":
			a.Security = "implicit"
		case "starttls", "none":
		default:
			return nil, fmt.Errorf("config %s: account %q: invalid security %q (implicit|starttls|none)", path, a.Name, a.Security)
		}
	}
	return cfg, nil
}

func findAccount(cfg *Config, name string) (*Account, error) {
	if name == "" {
		return nil, nil
	}
	for i := range cfg.Accounts {
		if strings.EqualFold(cfg.Accounts[i].Name, name) {
			return &cfg.Accounts[i], nil
		}
	}
	return nil, fmt.Errorf("no account named %q", name)
}
