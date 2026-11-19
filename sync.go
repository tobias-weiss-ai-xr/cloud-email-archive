package main

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
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

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

// syncAccount fetches every configured (or all selectable) folder of one account.
// One failing folder does not abort the others, but the returned error names
// every failure so a cron-driven sync can alert. Note: go-imap v2 beta has no
// context-aware operations, so there is deliberately no ctx parameter — a
// hung connection is bounded by the server's TCP timeouts.
func syncAccount(cfg *Config, a *Account, arc *Archive, st *State, log *slog.Logger) error {
	pw, err := accountPassword(a)
	if err != nil {
		return err
	}
	c, err := dial(a)
	if err != nil {
		return fmt.Errorf("%s: dial: %w", a.Name, err)
	}
	defer c.Close()
	if err := c.Login(a.User, pw).Wait(); err != nil {
		return fmt.Errorf("%s: login: %w", a.Name, err)
	}
	if a.Security == "none" {
		log.Warn("account uses security=none (plaintext IMAP)", "account", a.Name)
	}
	log.Info("connected", "account", a.Name, "host", a.Host)

	folders, missing, err := selectFolders(c, a, log)
	if err != nil {
		return err
	}
	var errs []error
	for _, folder := range folders {
		if err := syncFolder(c, a, folder, arc, st, log); err != nil {
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
	return errors.Join(errs...)
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

func syncFolder(c *imapclient.Client, a *Account, folder string, arc *Archive, st *State, log *slog.Logger) error {
	sel, err := c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return fmt.Errorf("select %q: %w", folder, err)
	}
	fs := st.folder(a.Name, folder)
	if fs.UIDValidity != 0 && fs.UIDValidity != sel.UIDValidity {
		log.Warn("UIDVALIDITY changed, refetching folder", "account", a.Name, "folder", folder,
			"old", fs.UIDValidity, "new", sel.UIDValidity)
		fs.UIDs = nil
	}
	fs.UIDValidity = sel.UIDValidity

	present, err := enumerateUIDs(c, sel.NumMessages)
	if err != nil {
		return fmt.Errorf("enumerate %q: %w", folder, err)
	}

	have := make(map[uint32]bool, len(fs.UIDs))
	for _, u := range fs.UIDs {
		have[u] = true
	}
	var todo []imap.UID
	for _, uid := range present {
		if !have[uint32(uid)] {
			todo = append(todo, uid)
		}
	}
	if len(todo) == 0 {
		log.Debug("up to date", "account", a.Name, "folder", folder, "count", len(present))
		return nil
	}
	log.Info("fetching new", "account", a.Name, "folder", folder, "new", len(todo), "total", len(present))

	fetched, err := fetchAndArchive(c, a, folder, arc, todo, log)
	if err != nil {
		return err
	}
	fs.UIDs = append(fs.UIDs, fetched...)
	return nil
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
func fetchAndArchive(c *imapclient.Client, a *Account, folder string, arc *Archive, todo []imap.UID, log *slog.Logger) ([]uint32, error) {
	uidSet := imap.UIDSetNum(todo...)
	cmd := c.Fetch(uidSet, &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{Peek: true}},
	})
	defer cmd.Close()

	var fetched []uint32
	var totalAdd, totalNew int64
	archived := 0
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
					if err != nil {
						return fetched, err
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
			log.Warn("fetch response without UID, skipping", "account", a.Name, "folder", folder)
			continue
		}
		totalAdd += int64(len(body))
		written, err := arc.put(a.Name, body)
		if err != nil {
			return fetched, err
		}
		if written {
			archived++
			totalNew += int64(len(body))
		}
		fetched = append(fetched, uint32(uid))
	}
	if err := cmd.Close(); err != nil {
		return fetched, err
	}
	log.Info("stored", "account", a.Name, "folder", folder, "new_messages", archived,
		"new_bytes", bytesCount(totalNew), "raw_bytes", bytesCount(totalAdd), "uids_remembered", len(fetched))
	return fetched, nil
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
