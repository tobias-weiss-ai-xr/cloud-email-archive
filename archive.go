package main

// Archive layer: age-encrypted, content-addressed message blobs.
//
// One file per message: <account>_<sha256 of raw message>.age
// Content-addressing gives dedup for free (identical bytes → same filename,
// already present → skipped) and opaque filenames for the storage provider.
// Decryption is authenticated (age AEAD): any corruption fails with an error,
// which is what `verify` relies on.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"net/mail"
)

type Archive struct {
	dir string
	id  *age.X25519Identity
}

// writeNewKey generates a fresh age identity and stores it at keyFile (0700 dir,
// 0600 file). Prints the recipient (public) part for reference.
func writeNewKey(keyFile string) error {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote key to %s\n", keyFile)
	fmt.Printf("recipient (public): %s\n", id.Recipient())
	fmt.Println("KEEP THIS KEY SAFE — it is the only way to decrypt the archive.")
	return nil
}

// loadKey reads the age secret key from keyFile.
func loadKey(keyFile string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w (run `cloud-email-archive keygen` first)", keyFile, err)
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", keyFile, err)
	}
	return id, nil
}

func newArchive(dir string, id *age.X25519Identity) *Archive {
	return &Archive{dir: dir, id: id}
}

func blobName(account string, raw []byte) string {
	sum := sha256.Sum256(raw)
	return account + "_" + hex.EncodeToString(sum[:]) + ".age"
}

func blobPath(dir, name string) string { return filepath.Join(dir, name) }

// put stores msg under content-addressed name; returns true if newly written.
func (a *Archive) put(account string, raw []byte) (written bool, err error) {
	name := blobName(account, raw)
	p := blobPath(a.dir, name)
	if _, err := os.Stat(p); err == nil {
		return false, nil // already archived
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return false, err
	}
	// unique tmp file per write so concurrent sync runs (e.g. two machines
	// syncing the same share) never clobber each other's in-progress blob
	tmp, err := os.CreateTemp(a.dir, name+".tmp")
	if err != nil {
		return false, err
	}
	cleanup := func() { tmp.Close(); os.Remove(tmp.Name()) }
	w, err := age.Encrypt(tmp, a.id.Recipient())
	if err != nil {
		cleanup()
		return false, err
	}
	if _, err := w.Write(raw); err != nil {
		cleanup()
		return false, err
	}
	if err := w.Close(); err != nil {
		cleanup()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return false, err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return false, err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		os.Remove(tmp.Name())
		return false, err
	}
	return true, nil
}

// get decrypts a single blob from the archive into the raw message.
func (a *Archive) get(name string) ([]byte, error) {
	f, err := os.Open(filepath.Join(a.dir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, a.id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// blobs lists archive files as (name, path, size) sorted by name.
type blob struct {
	name string
	path string
	size int64
}

func (a *Archive) blobs() ([]blob, error) {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []blob
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".age") {
			continue
		}
		info, _ := e.Info()
		out = append(out, blob{name: e.Name(), path: filepath.Join(a.dir, e.Name()), size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// accountOf derives the account name from a blob filename. The SHA-256 hash
// never contains '_', so splitting at the LAST underscore is safe even for
// account names that themselves contain underscores (e.g. "uni_mail").
func accountOf(name string) string {
	if i := strings.LastIndexByte(name, '_'); i > 0 {
		return name[:i]
	}
	return ""
}

// walk decrypts blobs and calls fn with each result; blobs of another account
// are skipped before decryption when account is non-empty. Stop early via the
// callback's error (e.g. errStop for limits).
func (a *Archive) walk(account string, fn func(msgRef) error) error {
	blobs, err := a.blobs()
	if err != nil {
		return err
	}
	for _, b := range blobs {
		if account != "" && !strings.EqualFold(accountOf(b.name), account) {
			continue // filter before decrypt: wrong-account blobs cost nothing
		}
		raw, err := a.get(b.name)
		if err != nil {
			return fmt.Errorf("%s: %w", b.name, err)
		}
		if err := fn(msgRef{account: accountOf(b.name), path: b.path, raw: raw}); err != nil {
			return err
		}
	}
	return nil
}

// msgRef is a decrypted message reference with its raw RFC822 bytes.
type msgRef struct {
	account string
	path    string
	raw     []byte
}

// parseHeaders extracts date/from/subject from raw RFC822 bytes. Folded
// headers (continuation lines starting with blank/tab) are unfolded; the first
// occurrence of each header wins; an unparsable or missing Date yields the
// Unix epoch.
func parseHeaders(raw []byte) (date time.Time, from, subject string) {
	date = time.Unix(0, 0)
	// normalize any line ending to CRLF
	crlf := bytes.ReplaceAll(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
	idx := bytes.Index(crlf, []byte("\r\n\r\n"))
	if idx < 0 {
		return
	}
	// unfold: continuation lines are appended to the preceding header line
	var lines [][]byte
	for _, line := range bytes.Split(crlf[:idx], []byte("\r\n")) {
		if len(lines) > 0 && len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			cont := append([]byte(" "), bytes.TrimLeft(line, " \t")...)
			lines[len(lines)-1] = append(lines[len(lines)-1], cont...)
			continue
		}
		lines = append(lines, line)
	}
	for _, line := range lines {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(string(line[:colon])))
		val := strings.TrimSpace(string(line[colon+1:]))
		switch key {
		case "date":
			if date.Equal(time.Unix(0, 0)) {
				if t, err := mail.ParseDate(val); err == nil {
					date = t
				}
			}
		case "from":
			if from == "" {
				from = val
			}
		case "subject":
			if subject == "" {
				subject = val
			}
		}
	}
	return
}
