package main

// View commands: list, search, extract, verify. All decrypt locally; nothing
// here ever touches the network or the synced folder's plaintext.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// printMsg renders one message line for list/search.
func printMsg(account string, raw []byte) {
	date, from, subject := parseHeaders(raw)
	fmt.Printf("%-11s %s  %-44s  %s\n", account, date.Format("2006-01-02"), truncate(subject, 44), truncate(from, 30))
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	limit := fs.Int("limit", 0, "max messages (default all)")
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	count := 0
	err = env.arc.walk(env.account, func(r msgRef) error {
		if *limit > 0 && count >= *limit {
			return errStop
		}
		printMsg(r.account, r.raw)
		count++
		return nil
	})
	if err == errStop {
		err = nil
	}
	if err == nil && count == 0 {
		fmt.Println("(no messages in archive)")
	}
	return err
}

func cmdSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	rawScan := fs.Bool("raw", false, "exhaustive scan over raw mail bytes, skip the index")
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("search needs a term")
	}
	term := strings.ToLower(strings.Join(fs.Args(), " "))
	term = strings.ReplaceAll(term, "\r", "")

	// trigram lookups need ≥3 characters; shorter terms silently exhaustively
	// scan the archive, so say why it is slow
	if !*rawScan && len(term) < 3 {
		fmt.Fprintf(os.Stderr, "term shorter than 3 characters; using exhaustive raw scan\n")
	}
	if !*rawScan && len(term) >= 3 {
		matches, err := searchIndexed(env, term)
		if err == nil {
			fmt.Printf("%d match(es)\n", matches)
			return nil
		}
		fmt.Fprintf(os.Stderr, "search index unavailable (%v); falling back to raw scan\n", err)
	}

	// raw path: exact byte-substring over full decrypted mail, no index
	matches := 0
	err = env.arc.walk(env.account, func(r msgRef) error {
		if !strings.Contains(strings.ToLower(string(r.raw)), term) {
			return nil
		}
		printMsg(r.account, r.raw)
		matches++
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("%d match(es)\n", matches)
	return nil
}

// cmdIndex builds/updates the search index on demand (sync does it
// automatically). Purely derived: safe to run any time, safe to delete.
func cmdIndex(args []string) error {
	fs := flag.NewFlagSet("index", flag.ContinueOnError)
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	// single-writer: index rewrites the same segments a running sync writes
	lock, err := lockInstance(env.cfg.StateFile)
	if err != nil {
		return err
	}
	defer lock.release()
	// freshness probe: if some segment's coverage hash already matches the
	// current blob set, there is nothing to do — say so instead of implying
	// a rebuild took place
	blobs, err := env.arc.blobs()
	if err != nil {
		return err
	}
	names := make([]string, len(blobs))
	for i, b := range blobs {
		names[i] = b.name
	}
	want := coverageHash(names)
	if segs, _ := listSegments(env.arc); len(segs) > 0 {
		for _, sn := range segs {
			if h, err := segmentCoverageHash(env.arc, sn); err == nil && h == want {
				fmt.Printf("index: up to date (%d blob(s), %d segment(s))\n", len(blobs), len(segs))
				return nil
			}
		}
	}
	segs, err := ensureIndex(env.arc)
	if err != nil {
		// honest gap: unreachable — ensureIndex re-lists the blobs that
		// succeeded above, against the same directory with the same perms
		return err
	}
	fmt.Printf("index: %d blob(s) covered, %d segment(s)\n", len(blobs), segs)
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
		return errors.New("extract needs -dir OUT")
	}
	n := 0
	err = env.arc.walk(env.account, func(r msgRef) error {
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
		if !wantAccount(env.account, accountOf(b.name)) {
			skipped++
			continue // other account's blob: not our problem, don't decrypt
		}
		raw, err := env.arc.get(b.name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", b.name, err)
			bad++
			continue
		}
		// content-addressing guarantee: the filename must be the SHA-256 of
		// the decrypted payload — catches renames, copy bugs, provider mangling
		if want := blobName(accountOf(b.name), raw); want != b.name {
			fmt.Fprintf(os.Stderr, "FAIL  %s: hash mismatch (content hashes to %s)\n", b.name, want)
			bad++
			continue
		}
		ok++
	}
	fmt.Printf("verify: %d ok, %d failed, %d skipped\n", ok, bad, skipped)
	if bad > 0 {
		return fmt.Errorf("%d blob(s) failed decryption", bad)
	}
	return nil
}

var errStop = errors.New("stop")

// truncate shortens s to at most n display columns (runes), appending an
// ellipsis. Rune-safe: never splits a multi-byte character.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
