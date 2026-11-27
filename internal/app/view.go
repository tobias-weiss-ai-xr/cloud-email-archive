package app

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

// printMsg renders one message line for list/search. folder is the first
// (sorted) folder holding the blob, "-" when the state has no attribution
// (blob predates folder bookkeeping, or no usable state file).
func printMsg(account, folder string, raw []byte) {
	date, from, subject := parseHeaders(raw)
	fmt.Printf("%-11s %-16s %s  %-44s  %s\n", account, truncate(folder, 16), date.Format("2006-01-02"), truncate(subject, 44), truncate(from, 30))
}

// folderLabel resolves a blob name to its display folder via the state's
// blob→folder index. Multiple folders show joined; unknown blobs show "-".
func folderLabel(idx map[string][]string, blobName string) string {
	fs := idx[blobName]
	if len(fs) == 0 {
		return "-"
	}
	return strings.Join(fs, ",")
}

// stateIndex loads the blob→folder index best-effort: a missing or
// unreadable state file must never break a read command — it only costs
// the folder column.
func stateIndex(env *cmdEnv) map[string][]string {
	st, err := loadState(env.cfg.StateFile, env.arc.id)
	if err != nil {
		return nil
	}
	return st.blobFolders()
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	limit := fs.Int("limit", 0, "max messages (default all)")
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	idx := stateIndex(env)
	count := 0
	err = env.arc.walk(env.account, func(r msgRef) error {
		if *limit > 0 && count >= *limit {
			return errStop
		}
		printMsg(r.account, folderLabel(idx, filepath.Base(r.path)), r.raw)
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
	idx := stateIndex(env)
	matches := 0
	err = env.arc.walk(env.account, func(r msgRef) error {
		if !strings.Contains(strings.ToLower(string(r.raw)), term) {
			return nil
		}
		printMsg(r.account, folderLabel(idx, filepath.Base(r.path)), r.raw)
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
	dedup := fs.Bool("dedup", false, "write each message once even if it lives in several folders")
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("extract needs -dir OUT")
	}
	// folder attribution comes from state; blobs the state cannot attribute
	// (predating the bookkeeping) fall back to OUT/<account>/<hash>.eml
	idx := stateIndex(env)
	n := 0
	err = env.arc.walk(env.account, func(r msgRef) error {
		hash := strings.TrimSuffix(filepath.Base(r.path), ".age")
		folders := idx[filepath.Base(r.path)]
		if *dedup && len(folders) > 1 {
			folders = folders[:1] // sorted: deterministic folder choice
		}
		if len(folders) == 0 {
			folders = []string{""} // unfiled: directly under the account dir
		}
		for _, folder := range folders {
			outDir := filepath.Join(*dir, r.account)
			if folder != "" { // "" = unfiled sentinel: no folder level
				outDir = filepath.Join(outDir, safeFolder(folder))
			}
			if err := os.MkdirAll(outDir, 0o700); err != nil {
				return err
			}
			out := filepath.Join(outDir, hash+".eml")
			if err := os.WriteFile(out, r.raw, 0o600); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("wrote %d message(s) to %s\n", n, *dir)
	return nil
}

// safeFolder turns an IMAP folder name into a portable directory path:
// one level per "/" component, server-controlled names never escape the
// output dir and never contain filesystem-hostile characters.
func safeFolder(folder string) string {
	parts := strings.Split(folder, "/")
	for i, p := range parts {
		p = strings.Map(func(r rune) rune {
			if r < 0x20 || strings.ContainsRune(`<>:"\|?*`, r) {
				return '_'
			}
			return r
		}, p)
		switch p {
		case ".", "..":
			p = "_" // traversal components become literal "_"
		}
		p = strings.TrimRight(p, ". ") // windows: trailing dots/spaces invalid
		if len(p) > 200 {
			p = p[:200] // component length cap; server controls the name
		}
		parts[i] = p // "" is fine: filepath.Join skips empty components
	}
	return filepath.Join(parts...)
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
