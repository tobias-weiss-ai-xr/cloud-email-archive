package main

// View commands: list, search, extract, verify. All decrypt locally; nothing
// here ever touches the network or the synced folder's plaintext.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	limit := fs.Int("limit", 0, "max messages (default all)")
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	count := 0
	err = env.arc.walk(func(r msgRef) error {
		if !wantAccount(env.acc, r.account) {
			return nil
		}
		if *limit > 0 && count >= *limit {
			return errStop
		}
		date, from, subject := parseHeaders(r.raw)
		fmt.Printf("%-11s %s  %-44s  %s\n", r.account, date.Format("2006-01-02"), truncate(subject, 44), truncate(from, 30))
		count++
		return nil
	})
	if err == errStop {
		err = nil
	}
	return err
}

func cmdSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("search needs a term")
	}
	term := strings.ToLower(strings.Join(fs.Args(), " "))
	matches := 0
	err = env.arc.walk(func(r msgRef) error {
		if !wantAccount(env.acc, r.account) {
			return nil
		}
		if !strings.Contains(strings.ToLower(string(r.raw)), term) {
			return nil
		}
		date, from, subject := parseHeaders(r.raw)
		fmt.Printf("%-11s %s  %-44s  %s\n", r.account, date.Format("2006-01-02"), truncate(subject, 44), truncate(from, 30))
		matches++
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("%d match(es)\n", matches)
	return nil
}

func cmdExtract(args []string) error {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	dir := fs.String("dir", "", "output directory (required)")
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("extract needs -dir OUT")
	}
	n := 0
	err = env.arc.walk(func(r msgRef) error {
		if !wantAccount(env.acc, r.account) {
			return nil
		}
		outDir := filepath.Join(*dir, r.account)
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			return err
		}
		out := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(r.path), ".age")+".eml")
		if err := os.WriteFile(out, r.raw, 0o600); err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("wrote %d message(s) to %s\n", n, *dir)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	blobs, err := env.arc.blobs()
	if err != nil {
		return err
	}
	bad, ok, skipped := 0, 0, 0
	for _, b := range blobs {
		if !wantAccount(env.acc, accountOf(b.name)) {
			skipped++
			continue
		}
		if _, err := env.arc.get(env.cfg.ArchiveDir, b.name); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", b.name, err)
			bad++
		} else {
			ok++
		}
	}
	fmt.Printf("verify: %d ok, %d failed, %d skipped\n", ok, bad, skipped)
	if bad > 0 {
		return fmt.Errorf("%d blob(s) failed decryption", bad)
	}
	return nil
}

var errStop = fmt.Errorf("stop")

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
