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
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return false, err
	}
	w, err := age.Encrypt(f, a.id.Recipient())
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return false, err
	}
	if _, err := w.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return false, err
	}
	if err := w.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return false, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// get decrypts a single blob into the raw message.
func (a *Archive) get(dir, name string) ([]byte, error) {
	f, err := os.Open(filepath.Join(dir, name))
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

// accountOf derives the account name from a blob filename.
func accountOf(name string) string {
	if i := strings.IndexByte(name, '_'); i > 0 {
		return name[:i]
	}
	return ""
}

// walk decrypts every blob and calls fn with the result; stop early via errStop.
func (a *Archive) walk(fn func(msgRef) error) error {
	blobs, err := a.blobs()
	if err != nil {
		return err
	}
	for _, b := range blobs {
		raw, err := a.get(a.dir, b.name)
		if err != nil {
			return fmt.Errorf("%s: %w", b.name, err)
		}
		if err := fn(msgRef{account: accountOf(b.name), path: b.path, raw: raw}); err != nil {
			return err
		}
	}
	return nil
}

// msgRef is a decrypted message with header fields for list/search/extract.
type msgRef struct {
	account string
	path    string
	raw     []byte
	date    time.Time
	from    string
	subject string
}

// parseHeaders extracts date/from/subject from raw RFC822 bytes.
func parseHeaders(raw []byte) (date time.Time, from, subject string) {
	date = time.Unix(0, 0)
	// normalize CRLF/LF to CRLF without double-adding \r
	lf := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
	idx := bytes.Index(crlf, []byte("\r\n\r\n"))
	if idx < 0 {
		return
	}
	hdr := crlf[:idx]
	for _, line := range bytes.Split(hdr, []byte("\r\n")) {
		// only first occurrence of each header matters; headers may be folded
		line = bytes.TrimPrefix(line, []byte("\r"))
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(string(line[:colon])))
		val := strings.TrimSpace(string(line[colon+1:]))
		switch key {
		case "date":
			if date.IsZero() || date.Equal(time.Unix(0, 0)) {
				if t, err := time.Parse(time.RFC1123Z, val); err == nil {
					date = t
				} else if t, err := time.Parse(time.RFC1123, val); err == nil {
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
