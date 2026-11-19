package main

// cloud-email-archive — encrypted email archive on next.hessenbox (or any synced folder).
// Single static binary: fetch (IMAP) + encrypt (age) + archive, cross-platform.

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const usageText = `cloud-email-archive — encrypted email archive synced to a cloud folder

Commands:
  keygen              generate a new age key (run once)
  sync                fetch IMAP accounts, encrypt new mail into the archive
  list                show message headers from the archive (decrypts locally)
  search TERM         full-text search over archived messages
  extract             write decrypted messages as .eml into a directory
  verify              decrypt-check every blob in the archive
  version

Config:  $CLOUD_EMAIL_ARCHIVE_CONFIG or ~/.config/cloud-email-archive/config.toml
Key:     ~/.config/cloud-email-archive/key.txt  (never put inside the synced folder)

Run "cloud-email-archive <cmd> -h" for command-specific flags.
`

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if len(os.Args) < 2 {
		fmt.Print(usageText)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "sync":
		err = cmdSync(os.Args[2:], log)
	case "list":
		err = cmdList(os.Args[2:])
	case "search":
		err = cmdSearch(os.Args[2:])
	case "extract":
		err = cmdExtract(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "version":
		fmt.Println("cloud-email-archive 0.1.0")
	case "-h", "help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type cmdEnv struct {
	cfg *Config
	arc *Archive
	acc *Account // nil = all accounts
}

// loadCfgEnv parses flags, loads config (with -config override) and the key.
func loadCfgEnv(fs *flag.FlagSet, args []string) (*cmdEnv, error) {
	cfgPath := fs.String("config", "", "config file")
	account := fs.String("account", "", "only this account")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *cfgPath == "" {
		*cfgPath = getenvDefault("CLOUD_EMAIL_ARCHIVE_CONFIG", defaultConfigPath())
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return nil, err
	}
	env := &cmdEnv{cfg: cfg}
	if *account != "" {
		acc, err := findAccount(cfg, *account)
		if err != nil {
			return nil, err
		}
		env.acc = acc
	}
	env.arc, err = openArchive(cfg)
	if err != nil {
		return nil, err
	}
	return env, nil
}

func cmdSync(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	cfg, arc := env.cfg, env.arc
	if env.acc != nil {
		filtered := *env.cfg
		filtered.Accounts = []Account{*env.acc}
		cfg = &filtered
	}
	if len(cfg.Accounts) == 0 {
		return fmt.Errorf("no accounts configured (add [[accounts]] sections to %s)", fs.Arg(0))
	}

	st, err := loadState(cfg.StateFile)
	if err != nil {
		return err
	}
	ctx := context.Background()
	for i := range cfg.Accounts {
		if err := syncAccount(ctx, cfg, &cfg.Accounts[i], arc, st, log); err != nil {
			log.Error("sync failed", "account", cfg.Accounts[i].Name, "err", err)
		}
	}
	if err := st.save(cfg.StateFile); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	log.Info("sync done", "archive", cfg.ArchiveDir)
	return nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("output", "", "key file (default ~/.config/cloud-email-archive/key.txt)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		*out = defaultKeyPath()
	}
	return writeNewKey(*out)
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultConfigPath() string {
	return filepath.Join(userCfgDir(), "config.toml")
}

func defaultKeyPath() string {
	return filepath.Join(userCfgDir(), "key.txt")
}

func defaultStatePath() string {
	return filepath.Join(userCfgDir(), "state.json")
}

func userCfgDir() string {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "cloud-email-archive"
	}
	return filepath.Join(cfgDir, "cloud-email-archive")
}

func openArchive(cfg *Config) (*Archive, error) {
	id, err := loadKey(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return newArchive(cfg.ArchiveDir, id), nil
}

func wantAccount(acc *Account, name string) bool {
	return acc == nil || strings.EqualFold(acc.Name, name)
}
