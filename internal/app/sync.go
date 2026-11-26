package app

// IMAP sync: connect per account, select each folder read-only, enumerate UIDs,
// fetch BODY[] (peek, never marks \\Seen) for every UID not yet archived, write
// encrypted blobs into the synced archive dir. Append-only: nothing is ever
// removed from the archive, mirroring "never delete" archive semantics.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// accountPassword resolves the IMAP credential: explicit password wins,
// otherwise password_cmd is executed (sh) and trimmed of trailing newlines.
// Setting both is a misconfiguration — loadConfig rejects it.
func accountPassword(a *Account) (string, error) {
	if a.Password != "" {
		return a.Password, nil
	}
	if a.PasswordCmd != "" {
		out, err := exec.Command("sh", "-c", a.PasswordCmd).Output()
		if err != nil {
			return "", fmt.Errorf("password_cmd failed: %w", err)
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	}
	return "", fmt.Errorf("account %q: neither password nor password_cmd set", a.Name)
}

// dial opens the IMAP connection per the account's security setting:
// implicit TLS (default), STARTTLS, or none (warned about by syncAccount).
func dial(a *Account) (*imapclient.Client, error) {
	addr := net.JoinHostPort(a.Host, fmt.Sprint(a.Port))
	opts := &imapclient.Options{TLSConfig: &tls.Config{ServerName: a.Host, MinVersion: tls.VersionTLS12}}
	switch a.Security {
	case "starttls":
		return imapclient.DialStartTLS(addr, opts)
	case "none":
		return imapclient.DialInsecure(addr, opts)
	default:
		return imapclient.DialTLS(addr, opts)
	}
}

// syncStats aggregates what one sync added to the archive.
type syncStats struct {
	messages int64
	bytes    int64
}

// syncAccount fetches every configured (or all selectable) folder of one account.
// One failing folder does not abort the others, but the returned error names
// every failure so a cron-driven sync can alert. Note: go-imap v2 beta has no
// context-aware operations, so there is deliberately no ctx parameter — a
// hung connection is bounded by the server's TCP timeouts.
func syncAccount(cfg *Config, a *Account, arc *Archive, st *State, log *slog.Logger, before *time.Time) (syncStats, error) {
	pw, err := accountPassword(a)
	if err != nil {
		return syncStats{}, err
	}
	c, err := dial(a)
	if err != nil {
		return syncStats{}, fmt.Errorf("%s: dial: %w", a.Name, err)
	}
	defer c.Close()
	if err := c.Login(a.User, pw).Wait(); err != nil {
		return syncStats{}, fmt.Errorf("%s: login: %w", a.Name, err)
	}
	if a.Security == "none" {
		log.Warn("account uses security=none (plaintext IMAP)", "account", a.Name)
	}
	log.Info("connected", "account", a.Name, "host", a.Host)

	folders, missing, err := selectFolders(c, a, log)
	if err != nil {
		return syncStats{}, err
	}
	var errs []error
	var total syncStats
	for _, folder := range folders {
		s, err := syncFolder(c, a, folder, arc, st, log, before)
		total.add(s)
		if err != nil {
			log.Error("folder sync failed", "account", a.Name, "folder", folder, "err", err)
			errs = append(errs, fmt.Errorf("account %s, folder %s: %w", a.Name, folder, err))
		}
	}
	// a configured folder that vanished from the server is a misconfiguration
	// (renamed/deleted mailbox) — syncing silently nothing would hide it
	for _, m := range missing {
		log.Error("configured folder not found", "account", a.Name, "folder", m)
		errs = append(errs, fmt.Errorf("account %s: configured folder %q not found on server", a.Name, m))
	}
	return total, errors.Join(errs...)
}

func (s *syncStats) add(o syncStats) {
	s.messages += o.messages
	s.bytes += o.bytes
}

// selectFolders returns the folder names to archive: the configured list, or
// all selectable folders when the config says "*" or lists nothing. Configured
// folders missing on the server are reported as missing (caller decides).
func selectFolders(c *imapclient.Client, a *Account, log *slog.Logger) (found, missing []string, err error) {
	want := a.Folders
	all := false
	for _, f := range want {
		if f == "*" {
			all = true
		}
	}
	if !all && len(want) == 0 {
		all = true
	}

	scmd := c.List("", "*", &imap.ListOptions{})
	var available []string
	for {
		ld := scmd.Next()
		if ld == nil {
			break
		}
		noselect := false
		for _, attr := range ld.Attrs {
			if attr == imap.MailboxAttrNoSelect {
				noselect = true
				break
			}
		}
		if noselect {
			continue
		}
		available = append(available, ld.Mailbox)
	}
	if err := scmd.Close(); err != nil {
		return nil, nil, err
	}

	if all {
		return available, nil, nil
	}
	lower := map[string]bool{}
	for _, f := range available {
		lower[strings.ToLower(f)] = true
	}
	for _, f := range want {
		if lower[strings.ToLower(f)] {
			found = append(found, f)
		} else {
			log.Warn("folder not found on server", "account", a.Name, "folder", f)
			missing = append(missing, f)
		}
	}
	return found, missing, nil
}

func syncFolder(c *imapclient.Client, a *Account, folder string, arc *Archive, st *State, log *slog.Logger, before *time.Time) (syncStats, error) {
	sel, err := c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return syncStats{}, fmt.Errorf("select %q: %w", folder, err)
	}
	fs := st.folder(a.Name, folder)
	if fs.UIDValidity != 0 && fs.UIDValidity != sel.UIDValidity {
		log.Warn("UIDVALIDITY changed, refetching folder", "account", a.Name, "folder", folder,
			"old", fs.UIDValidity, "new", sel.UIDValidity)
		fs.UIDs = nil
	}
	fs.UIDValidity = sel.UIDValidity

	var present []imap.UID
	if before != nil {
		present, err = searchUIDsBefore(c, *before)
		if err != nil {
			return syncStats{}, fmt.Errorf("search before %s: %w", before.Format("2006-01-02"), err)
		}
	} else {
		present, err = enumerateUIDs(c, sel.NumMessages)
		if err != nil {
			return syncStats{}, fmt.Errorf("enumerate %q: %w", folder, err)
		}
	}

	have := make(map[uint32]bool, len(fs.UIDs))
	for _, u := range fs.UIDs {
		have[uint32(u)] = true
	}
	var todo []imap.UID
	for _, uid := range present {
		if !have[uint32(uid)] {
			todo = append(todo, uid)
		}
	}
	if before == nil {
		// full enumeration sees every message on the server: any remembered
		// UID that is not present was expunged elsewhere (other client, or a
		// crash between expire's UID EXPUNGE and the state save) — drop it
		// from state so expire never re-considers it. The blob stays; the
		// archive is append-only. Never prune on a -before sync: there the
		// present set is partial, and "not present" just means "after the
		// cutoff".
		presentSet := make(map[uint32]bool, len(present))
		for _, uid := range present {
			presentSet[uint32(uid)] = true
		}
		keep := fs.UIDs[:0]
		for _, u := range fs.UIDs {
			if presentSet[uint32(u)] {
				keep = append(keep, u)
			}
		}
		fs.UIDs = keep
	}
	if len(todo) == 0 {
		log.Debug("up to date", "account", a.Name, "folder", folder, "count", len(present))
		return syncStats{}, nil
	}
	log.Info("fetching new", "account", a.Name, "folder", folder, "new", len(todo), "total", len(present))

	fetched, s, err := fetchAndArchive(c, a, folder, arc, todo, log)
	if err != nil {
		return s, err
	}
	fs.UIDs = append(fs.UIDs, fetched...)
	return s, nil
}

// searchUIDsBefore returns the UIDs of all messages whose INTERNALDATE is
// before cutoff (server-side UID SEARCH BEFORE — date-only, exclusive). This
// is the date-scoped alternative to enumerateUIDs for "archive old mail".
//
// Fault injection for the SEARCH reply lives in the raw script server
// (TestSyncBeforeSearchTaggedNO); the session hook cannot reach Search.
// The non-UID-set reply branch is defense for future client versions:
// against beta.9 it is unreachable — UIDSearch always initializes All as
// an (empty) UIDSet, and the client's handleSearch only ever appends to it.
func searchUIDsBefore(c *imapclient.Client, cutoff time.Time) ([]imap.UID, error) {
	data, err := c.UIDSearch(&imap.SearchCriteria{Before: cutoff}, nil).Wait()
	if err != nil {
		return nil, err
	}
	set, ok := data.All.(imap.UIDSet)
	if !ok {
		return nil, fmt.Errorf("search returned no UID set (%T)", data.All)
	}
	uids, _ := set.Nums()
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	return uids, nil
}

// enumerateUIDs returns all message UIDs currently in the selected mailbox.
func enumerateUIDs(c *imapclient.Client, numMessages uint32) ([]imap.UID, error) {
	if numMessages == 0 {
		return nil, nil
	}
	seq := imap.SeqSetNum()
	seq.AddRange(1, numMessages)
	cmd := c.Fetch(seq, &imap.FetchOptions{UID: true})
	defer cmd.Close()
	var uids []imap.UID
	for {
		msg := cmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if d, ok := item.(imapclient.FetchItemDataUID); ok {
				uids = append(uids, d.UID)
			}
		}
	}
	return uids, cmd.Close()
}

// fetchAndArchive streams BODY[] for the given UIDs and stores new messages.
// Returned stats count only newly written blobs; dedup hits fetch the bytes
// but add nothing.
func fetchAndArchive(c *imapclient.Client, a *Account, folder string, arc *Archive, todo []imap.UID, log *slog.Logger) ([]uint32, syncStats, error) {
	uidSet := imap.UIDSetNum(todo...)
	cmd := c.Fetch(uidSet, &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{Peek: true}},
	})
	defer cmd.Close()

	var fetched []uint32
	var s syncStats
	var totalAdd int64
	for {
		msg := cmd.Next()
		if msg == nil {
			break
		}
		var uid imap.UID
		var body []byte
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			switch item := item.(type) {
			case imapclient.FetchItemDataUID:
				uid = item.UID
			case imapclient.FetchItemDataBodySection:
				if item.Literal != nil {
					b, err := io.ReadAll(item.Literal)
					// a dropped connection can surface as a short read with a
					// nil read error (the client's literal reader treats EOF as
					// end-of-literal) — archiving half a message would be worse
					// than failing the run, so the promised size is verified
					if err == nil && item.Literal.Size() != int64(len(b)) {
						err = fmt.Errorf("body truncated: got %d of %d bytes", len(b), item.Literal.Size())
					}
					if err != nil {
						return fetched, s, err
					}
					body = b
				}
			}
		}
		if len(body) == 0 {
			log.Warn("empty body, skipping", "account", a.Name, "folder", folder, "uid", uid)
			continue
		}
		if uid == 0 {
			// honest gap: unreachable against go-imap v2 beta.9 — it
			// discards UID-less FETCH responses unilaterally, so they never
			// reach this loop; kept as defense for future client versions
			log.Warn("fetch response without UID, skipping", "account", a.Name, "folder", folder)
			continue
		}
		totalAdd += int64(len(body))
		written, err := arc.put(a.Name, body)
		if err != nil {
			return fetched, s, err
		}
		if written {
			s.messages++
			s.bytes += int64(len(body))
		}
		fetched = append(fetched, uint32(uid))
	}
	if err := cmd.Close(); err != nil {
		return fetched, s, err
	}
	log.Info("stored", "account", a.Name, "folder", folder, "new_messages", s.messages,
		"new_bytes", bytesCount(s.bytes), "raw_bytes", bytesCount(totalAdd), "uids_remembered", len(fetched))
	return fetched, s, nil
}

func bytesCount(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
