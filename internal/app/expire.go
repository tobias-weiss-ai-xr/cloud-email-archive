package app

// expire: delete mail from the IMAP server after the archive provably holds
// a copy. The archive itself stays append-only — expire only frees space on
// the mail server. Safety gates, in order:
//  1. -before is required; without an explicit cutoff date nothing happens
//  2. candidates = server "BEFORE the cutoff" set ∩ UIDs remembered in state
//     (i.e. messages this tool has actually archived)
//  3. UIDVALIDITY guard: if the folder's UIDVALIDITY changed since the last
//     sync, the folder is skipped — stale UIDs could point at different
//     messages, and deleting those would lose mail
//  4. proof per message: fetch UID + INTERNALDATE + body, require the date to
//     be within scope and a decrypt-checked blob with the exact sha256 of the
//     body to exist in the archive; anything unproven is skipped, not deleted
//  5. dry-run by default: without -do the run only reports what would happen
//  6. deletion is UID-scoped: UID STORE \Deleted + UID EXPUNGE touch exactly
//     the proven set, never the whole mailbox

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// parseDateArg parses the YYYY-MM-DD date used by -before flags. The result is
// local midnight; IMAP BEFORE semantics are date-only and exclusive, so mail
// received on the cutoff date itself is out of scope.
func parseDateArg(s string) (time.Time, error) {
	t, err := time.ParseInLocation("2006-01-02", strings.TrimSpace(s), time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("want YYYY-MM-DD, got %q", s)
	}
	return t, nil
}

// proof is one message the archive demonstrably holds.
type proof struct {
	uid  imap.UID
	size int64
}

// cmdExpire implements `expire`: report (dry-run) or perform server-side
// deletion of mail whose content is provably in the archive.
func cmdExpire(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("expire", flag.ContinueOnError)
	beforeStr := fs.String("before", "", "delete mail received before this date, YYYY-MM-DD (required)")
	doIt := fs.Bool("do", false, "actually delete on the server (default: dry run)")
	env, err := loadCfgEnv(fs, args)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*beforeStr) == "" {
		return fmt.Errorf("expire requires -before YYYY-MM-DD (refusing to touch mail without an explicit cutoff)")
	}
	cutoff, err := parseDateArg(*beforeStr)
	if err != nil {
		return fmt.Errorf("-before: %w", err)
	}
	// single-writer: concurrent expire/sync runs would clobber the state file
	lock, err := lockInstance(env.cfg.StateFile)
	if err != nil {
		return err
	}
	defer lock.release()
	cfg, arc := env.cfg, env.arc
	if env.account != "" {
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

	st, err := loadState(cfg.StateFile)
	if err != nil {
		return err
	}

	mode := "dry run"
	if *doIt {
		mode = "DELETE"
	}
	var errs []error
	var deleted int64
	var freed int64
	for i := range cfg.Accounts {
		n, bytes, err := expireAccount(cfg, &cfg.Accounts[i], arc, st, cutoff, *doIt, log)
		deleted += n
		freed += bytes
		if err != nil {
			log.Error("expire failed", "account", cfg.Accounts[i].Name, "err", err)
			errs = append(errs, fmt.Errorf("account %s: %w", cfg.Accounts[i].Name, err))
		}
	}
	if *doIt {
		if err := st.save(cfg.StateFile); err != nil {
			// join, don't return early — deletions already happened
			errs = append(errs, fmt.Errorf("save state: %w", err))
		}
	}
	log.Info("expire done", "mode", mode, "before", cutoff.Format("2006-01-02"),
		"messages", deleted, "server_bytes_freed", bytesCount(freed))
	return errors.Join(errs...)
}

// expireAccount expires one account's folders and returns the number of
// messages handled (proven, and deleted when doIt) plus their total size.
func expireAccount(cfg *Config, a *Account, arc *Archive, st *State, cutoff time.Time, doIt bool, log *slog.Logger) (int64, int64, error) {
	log.Info("connecting", "account", a.Name, "host", a.Host)
	c, err := dial(a)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: dial: %w", a.Name, err)
	}
	defer c.Close()
	pw, err := accountPassword(a)
	if err != nil {
		return 0, 0, err
	}
	if err := c.Login(a.User, pw).Wait(); err != nil {
		return 0, 0, fmt.Errorf("%s: login: %w", a.Name, err)
	}
	folders, missing, err := selectFolders(c, a, log)
	if err != nil {
		return 0, 0, err
	}
	var errs []error
	var total int64
	var bytes int64
	for _, folder := range folders {
		n, b, err := expireFolder(c, a, folder, arc, st, cutoff, doIt, log)
		total += n
		bytes += b
		if err != nil {
			log.Error("folder expire failed", "account", a.Name, "folder", folder, "err", err)
			errs = append(errs, fmt.Errorf("account %s, folder %s: %w", a.Name, folder, err))
		}
	}
	// same misconfiguration rule as sync: a configured folder that vanished
	// from the server must not be silently skipped
	for _, m := range missing {
		errs = append(errs, fmt.Errorf("account %s: configured folder %q not found on server", a.Name, m))
	}
	return total, bytes, errors.Join(errs...)
}

// expireFolder proves and (when doIt) deletes one folder's in-scope mail.
func expireFolder(c *imapclient.Client, a *Account, folder string, arc *Archive, st *State, cutoff time.Time, doIt bool, log *slog.Logger) (int64, int64, error) {
	// survey in read-only mode; only an actual deletion needs write access,
	// so the select is writable iff -do was given
	sel, err := c.Select(folder, &imap.SelectOptions{ReadOnly: !doIt}).Wait()
	if err != nil {
		return 0, 0, fmt.Errorf("select: %w", err)
	}
	fs := st.folder(a.Name, folder)
	if fs.UIDValidity == 0 {
		log.Warn("folder never synced — refusing to expire (run sync first)",
			"account", a.Name, "folder", folder)
		return 0, 0, nil
	}
	if fs.UIDValidity != sel.UIDValidity {
		log.Warn("UIDVALIDITY changed since last sync — refusing to expire (stale UIDs would be unsafe)",
			"account", a.Name, "folder", folder, "state", fs.UIDValidity, "server", sel.UIDValidity)
		return 0, 0, nil
	}

	uids, err := searchUIDsBefore(c, cutoff)
	if err != nil {
		// fault injection for SEARCH lives in TestExpireSearchTaggedNO's raw
		// script server (the session hook cannot reach Search)
		return 0, 0, fmt.Errorf("search: %w", err)
	}
	have := make(map[uint32]bool, len(fs.UIDs))
	for _, u := range fs.UIDs {
		have[uint32(u)] = true
	}
	var cands []imap.UID
	for _, uid := range uids {
		if have[uint32(uid)] {
			cands = append(cands, uid)
		}
	}
	if len(cands) == 0 {
		log.Info("nothing to expire", "account", a.Name, "folder", folder)
		return 0, 0, nil
	}

	proved, err := proveHoldings(c, a, folder, arc, cands, cutoff, log)
	if err != nil {
		// reached via the truncation guard in proveHoldings
		// (TestExpireProofFetchTruncated's raw script server injects it)
		return 0, 0, err
	}
	if len(proved) == 0 {
		log.Warn("no in-scope message could be proven against the archive — nothing deleted",
			"account", a.Name, "folder", folder, "candidates", len(cands))
		return 0, 0, nil
	}
	var bytes int64
	provedSet := make(map[uint32]bool, len(proved))
	provedUIDs := make([]imap.UID, len(proved))
	for i, p := range proved {
		provedSet[uint32(p.uid)] = true
		provedUIDs[i] = p.uid
		bytes += p.size
	}

	if !doIt {
		fmt.Printf("dry run: %s/%s: would delete %d of %d in-scope message(s) (%s)\n",
			a.Name, folder, len(proved), len(cands), bytesCount(bytes))
		return int64(len(proved)), bytes, nil
	}

	uidSet := imap.UIDSetNum(provedUIDs...)
	if err := c.Store(uidSet, &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Silent: true,
		Flags:  []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		return 0, 0, fmt.Errorf("store \\Deleted: %w", err)
	}
	if err := c.UIDExpunge(uidSet).Close(); err != nil {
		return 0, 0, fmt.Errorf("uid expunge: %w", err)
	}
	keep := fs.UIDs[:0]
	for _, u := range fs.UIDs {
		if !provedSet[u] {
			keep = append(keep, u)
		}
	}
	fs.UIDs = keep
	fmt.Printf("deleted: %s/%s: deleted %d of %d in-scope message(s) (%s)\n",
		a.Name, folder, len(proved), len(cands), bytesCount(bytes))
	log.Info("expired", "account", a.Name, "folder", folder, "deleted", len(proved),
		"bytes", bytesCount(bytes), "kept", len(fs.UIDs))
	return int64(len(proved)), bytes, nil
}

// proveHoldings fetches each candidate once (UID + INTERNALDATE + body) and
// keeps only messages the archive demonstrably holds: exact sha256 match on a
// decrypt-checked blob, with the INTERNALDATE inside the requested window.
func proveHoldings(c *imapclient.Client, a *Account, folder string, arc *Archive, cands []imap.UID, cutoff time.Time, log *slog.Logger) ([]proof, error) {
	uidSet := imap.UIDSetNum(cands...)
	cmd := c.Fetch(uidSet, &imap.FetchOptions{
		UID:          true,
		InternalDate: true,
		BodySection:  []*imap.FetchItemBodySection{{Peek: true}},
	})
	defer cmd.Close()

	var proved []proof
	for {
		msg := cmd.Next()
		if msg == nil {
			break
		}
		var uid imap.UID
		var internal time.Time
		var body []byte
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			switch item := item.(type) {
			case imapclient.FetchItemDataUID:
				uid = item.UID
			case imapclient.FetchItemDataInternalDate:
				internal = item.Time
			case imapclient.FetchItemDataBodySection:
				if item.Literal != nil {
					b, err := io.ReadAll(item.Literal)
					// same truncation guard as sync.go's fetchAndArchive:
					// beta.9 swallows short reads with err=nil (EOF ends the
					// literal), so the promised size must be verified
					if err == nil && item.Literal.Size() != int64(len(b)) {
						err = fmt.Errorf("body truncated: got %d of %d bytes", len(b), item.Literal.Size())
					}
					if err != nil {
						return nil, err
					}
					body = b
				}
			}
		}
		if uid == 0 || internal.IsZero() || len(body) == 0 {
			log.Warn("incomplete fetch response, skipping", "account", a.Name, "folder", folder, "uid", uid)
			continue
		}
		if !internal.Before(cutoff) {
			// server drift guard: the SEARCH said "before", the message says
			// otherwise — trust the message, skip it
			log.Warn("INTERNALDATE outside requested window, skipping",
				"account", a.Name, "folder", folder, "uid", uid, "internaldate", internal.Format("2006-01-02"))
			continue
		}
		ok, err := archiveHolds(arc, a.Name, body)
		if err != nil {
			log.Warn("archive check failed, skipping", "account", a.Name, "folder", folder,
				"uid", uid, "err", err)
			continue
		}
		if !ok {
			log.Warn("archive does not hold this message, skipping", "account", a.Name,
				"folder", folder, "uid", uid)
			continue
		}
		proved = append(proved, proof{uid: uid, size: int64(len(body))})
	}
	// a tagged NO on the proof fetch means some candidates were never seen —
	// fail the run like sync does (they were skipped above, nothing deleted)
	if err := cmd.Close(); err != nil {
		return nil, err
	}
	return proved, nil
}

// archiveHolds verifies the archive contains an age-encrypted blob whose
// decrypted content is byte-identical to raw (content-addressed by sha256).
func archiveHolds(arc *Archive, account string, raw []byte) (bool, error) {
	sum := sha256.Sum256(raw)
	name := blobName(account, raw)
	path := filepath.Join(arc.dir, name)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err // e.g. ENOTDIR when the archive path is wrecked (tested)
	}
	dec, err := arc.get(name)
	if err != nil {
		return false, err // present but unreadable/corrupt — never delete on a hunch
	}
	decSum := sha256.Sum256(dec)
	return bytes.Equal(decSum[:], sum[:]), nil
}
