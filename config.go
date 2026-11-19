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
	cfgDir, _ := os.UserConfigDir()
	return &Config{
		ArchiveDir: filepath.Join(home, "cloud-email-archive"),
		KeyFile:    filepath.Join(cfgDir, "cloud-email-archive", "key.txt"),
		StateFile:  filepath.Join(cfgDir, "cloud-email-archive", "state.json"),
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
		panic("unreachable")
	}
	for i := range cfg.Accounts {
		a := &cfg.Accounts[i]
		a.Name = strings.TrimSpace(a.Name)
		a.Host = strings.TrimSpace(a.Host)
		if a.Port == 0 {
			a.Port = 993
		}
		switch a.Security {
		case "", "implicit":
			a.Security = "implicit"
		case "starttls", "none":
		default:
			return nil, fmt.Errorf("account %q: invalid security %q (implicit|starttls|none)", a.Name, a.Security)
		}
	}
	return cfg, nil
}

func findAccount(cfg *Config, name string) (*Account, error) {
	if name == "" {
		return nil, nil
	}
	for i := range cfg.Accounts {
		if cfg.Accounts[i].Name == name {
			return &cfg.Accounts[i], nil
		}
	}
	return nil, fmt.Errorf("no account named %q", name)
}
