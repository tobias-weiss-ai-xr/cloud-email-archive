package app

// cloud-email-archive — encrypted email archive synced to any cloud folder.
// Single static binary: fetch (IMAP) + encrypt (age) + archive, cross-platform.

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/term"
	"time"
)

// version is the single source for the `version` command; CI/release builds
// can stamp it with -ldflags "-X github.com/tobias-weiss-ai-xr/cloud-email-archive/internal/app.version=...".
var version = "0.1.0"

const usageText = `cloud-email-archive — encrypted email archive synced to a cloud folder

Commands:
  keygen              generate a new age key (run once)
  sync                fetch IMAP accounts, encrypt new mail into the archive
  index               build/update the encrypted search index (runs after sync)
  list                show message headers from the archive (decrypts locally)
  search TERM         full-text search over archived messages (--raw for byte scan)
  extract             write decrypted messages as .eml into a directory
  verify              decrypt-check every blob in the archive
  expire              delete server-side mail the archive provably holds
                      (dry run unless -do; requires -before YYYY-MM-DD)
  version

Config:  $CLOUD_EMAIL_ARCHIVE_CONFIG or ~/.config/cloud-email-archive/config.toml
Key:     ~/.config/cloud-email-archive/key.txt  (never put inside the synced folder)

Run "cloud-email-archive <cmd> -h" for command-specific flags.
`

// Run executes the CLI with the given arguments and returns the process
// exit code. Entry point for cmd/cea; kept free of os.Exit so tests can
// exercise the dispatch table.
func Run(args []string) int {
	return run(args)
}

// run executes one CLI invocation and returns the process exit code. Kept
// free of os.Exit so tests can exercise the dispatch table.
func run(args []string) int {
	if len(args) == 0 {
		fmt.Print(usageText)
		return 2
	}
	var err error
	switch args[0] {
	case "keygen":
		err = cmdKeygen(args[1:])
	case "sync":
		err = cmdSync(args[1:], slog.New(slog.NewTextHandler(os.Stderr, nil)))
	case "index":
		err = cmdIndex(args[1:])
	case "list":
		err = cmdList(args[1:])
	case "search":
		err = cmdSearch(args[1:])
	case "extract":
		err = cmdExtract(args[1:])
	case "expire":
		err = cmdExpire(args[1:], slog.New(slog.NewTextHandler(os.Stderr, nil)))
	case "verify":
		err = cmdVerify(args[1:])
	case "version":
		fmt.Println("cloud-email-archive " + version)
	case "-h", "-help", "--help", "help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usageText)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // usage already printed by the flag package
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

type cmdEnv struct {
	cfgPath string
	cfg     *Config
	arc     *Archive
	account string // -account filter: raw name (view commands) or resolved account (sync)
}

// loadCfgEnv parses flags and loads config (with -config override) and the key.
// The -account value is kept as a raw filter string; only sync resolves it
// against the config (read commands must also see accounts that have since
// been removed from the config — the archive is append-only).
func loadCfgEnv(fs *flag.FlagSet, args []string) (*cmdEnv, error) {
	cfgPath := fs.String("config", "", "config file")
	account := fs.String("account", "", "only this account")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *cfgPath == "" {
		*cfgPath = getenvDefault("CLOUD_EMAIL_ARCHIVE_CONFIG", defaultConfigPath())
	}
	env := &cmdEnv{cfgPath: *cfgPath, account: strings.TrimSpace(*account)}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return nil, err
	}
	env.cfg = cfg
	env.arc, err = openArchive(cfg)
	if err != nil {
		return nil, err
	}
	return env, nil
}

func cmdSync(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	beforeStr := fs.String("before", "", "only fetch mail received before this date (YYYY-MM-DD, exclusive); a later sync without -before picks up the rest")
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	var before *time.Time
	if *beforeStr != "" {
		t, err := parseDateArg(*beforeStr)
		if err != nil {
			return fmt.Errorf("-before: %w", err)
		}
		before = &t
	}
	// single-writer: concurrent syncs would clobber each other's state file
	lock, err := lockInstance(env.cfg.StateFile)
	if err != nil {
		return err
	}
	defer lock.release()
	cfg, arc := env.cfg, env.arc
	if env.account != "" {
		// sync requires a configured account (read commands don't)
		acc, err := findAccount(cfg, env.account)
		if err != nil {
			return err
		}
		filtered := *cfg
		filtered.Accounts = []Account{*acc}
		cfg = &filtered
	}
	if len(cfg.Accounts) == 0 {
		return fmt.Errorf("no accounts configured (add [[accounts]] sections to %s)", env.cfgPath)
	}

	st, err := loadState(cfg.StateFile, arc.id)
	if err != nil {
		return err
	}
	// leftovers from crashed runs pollute the synced folder forever — clean
	// up ones old enough that no concurrent writer can still be using them
	if err := sweepStaleTmp(cfg.ArchiveDir, 24*time.Hour); err != nil {
		log.Warn("could not sweep stale tmp files", "dir", cfg.ArchiveDir, "err", err)
	}
	// one failed account must not mask the others, but it must fail the run
	var errs []error
	var total syncStats
	for i := range cfg.Accounts {
		s, err := syncAccount(cfg, &cfg.Accounts[i], arc, st, log, before)
		total.add(s)
		if err != nil {
			log.Error("sync failed", "account", cfg.Accounts[i].Name, "err", err)
			errs = append(errs, fmt.Errorf("account %s: %w", cfg.Accounts[i].Name, err))
		}
	}
	if err := st.save(cfg.StateFile, arc.id); err != nil {
		// join, don't return early — account errors must still surface
		errs = append(errs, fmt.Errorf("save state: %w", err))
	}
	// keep the search index fresh; purely derived data — never fail the sync
	if _, err := ensureIndex(arc); err != nil {
		log.Warn("index update failed; search falls back to raw scan", "err", err)
	}
	log.Info("sync done", "archive", cfg.ArchiveDir,
		"new_messages", total.messages, "new_bytes", bytesCount(total.bytes))
	return errors.Join(errs...)
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("output", "", "key file (default ~/.config/cloud-email-archive/key.txt)")
	passphrase := fs.Bool("passphrase", false, "encrypt the key file with a passphrase (disk never holds the secret key in the clear)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		*out = defaultKeyPath()
	}
	var pass string
	if *passphrase {
		var err error
		if pass, err = resolvePassphrase(nil, true); err != nil {
			return err
		}
		if pass == "" {
			return errors.New("no passphrase provided (CEA_PASSPHRASE or interactive prompt)")
		}
	}
	return writeNewKey(*out, pass)
}

// resolvePassphrase returns the key passphrase from the environment
// (CEA_PASSPHRASE), the config (passphrase_cmd), or — interactive — from a
// hidden terminal prompt (askConfirm: prompt twice on keygen). No passphrase
// flag exists on purpose: command-line arguments are visible in ps/history.
// cfg may be nil (keygen has no config yet).
func resolvePassphrase(cfg *Config, askConfirm bool) (string, error) {
	if p := os.Getenv("CEA_PASSPHRASE"); p != "" {
		return p, nil
	}
	if cfg != nil && cfg.PassphraseCmd != "" {
		out, err := exec.Command("sh", "-c", cfg.PassphraseCmd).Output()
		if err != nil {
			return "", fmt.Errorf("passphrase_cmd failed: %w", err)
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("passphrase required but stdin is not a terminal (set CEA_PASSPHRASE or passphrase_cmd)")
	}
	fmt.Fprint(os.Stderr, "Enter passphrase: ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if !askConfirm {
		return string(p1), nil
	}
	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", errors.New("passphrases do not match")
	}
	return string(p1), nil
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
	// resolve the passphrase lazily: plaintext key files need none, and an
	// unnecessary non-interactive error would break scripted plaintext runs
	pass := ""
	if keyFileIsArmored(cfg.KeyFile) {
		var err error
		if pass, err = resolvePassphrase(cfg, false); err != nil {
			return nil, err
		}
	}
	id, err := loadKey(cfg.KeyFile, pass)
	if err != nil {
		return nil, err
	}
	return newArchive(cfg.ArchiveDir, id), nil
}

func wantAccount(filter, name string) bool {
	return filter == "" || strings.EqualFold(filter, name)
}
