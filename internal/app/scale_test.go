package app

// Scale harness for the 500 GB growth question: generates a deterministic
// mail corpus (text + base64 attachment mix, realistic proportions), archives
// it locally without IMAP, and leaves key + config behind so the real binary
// can be benchmarked from the shell (see docs/benchmark.md).
//
// Opt-in only — skipped unless CEA_SCALE_MB is set:
//
//	CEA_SCALE_MB=500 go test -run TestScaleCorpus -timeout 30m .
//	CEA_SCALE_MB=8192 go test -run TestScaleCorpus -timeout 60m .
//
// Output lands in CEA_SCALE_DIR (default /tmp/cea-scale): archive/, key.txt,
// config.toml, manifest with the zebra-token ground truth.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func scaleMail(rng *rand.Rand, i int) (raw []byte, textBytes int, kind string) {
	var b strings.Builder
	fmt.Fprintf(&b, "From: sender%d@example.de\r\nTo: inbox@example.de\r\nDate: Mon, 02 Jan 2006 15:04:05 +0100\r\nMessage-ID: <scale%d@test>\r\nSubject: scale mail %d\r\n", i, i, i)
	text := func(n int) string {
		var w strings.Builder
		// varied pseudoword vocabulary: real text has thousands of distinct
		// trigrams, not one repeated sentence (keeps index-size numbers honest)
		for w.Len() < n {
			lw := 3 + int(rng.Uint64()%9)
			for k := 0; k < lw; k++ {
				w.WriteByte('a' + byte(rng.Uint64()%26))
			}
			w.WriteByte(' ')
		}
		return w.String()
	}
	attach := func(ct string, bytesN int) string {
		payload := make([]byte, bytesN)
		for j := range payload {
			payload[j] = byte(rng.Uint32())
		}
		enc := base64.StdEncoding.EncodeToString(payload)
		var part strings.Builder
		fmt.Fprintf(&part, "--BB\r\nContent-Type: %s\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"f%d.bin\"\r\n\r\n", ct, i)
		for len(enc) > 0 {
			cut := 76
			if len(enc) < cut {
				cut = len(enc)
			}
			part.WriteString(enc[:cut])
			part.WriteString("\r\n")
			enc = enc[cut:]
		}
		return part.String()
	}
	switch rng.Intn(10) { // 6/10 text, 2/10 pdf, 1/10 image, 1/10 calendar-or-zip
	case 0, 1, 2, 3, 4, 5: // 55 % plain text+html
		kind = "text"
		body := text(4000 + rng.Intn(4000))
		b.WriteString("Content-Type: multipart/alternative; boundary=AA\r\n\r\n--AA\r\nContent-Type: text/plain\r\n\r\n")
		b.WriteString(body)
		if i%50 == 0 {
			b.WriteString("\r\ncorpus token: zebraTAIL\r\n")
		}
		b.WriteString("\r\n--AA\r\nContent-Type: text/html\r\n\r\n<p>")
		b.WriteString(body)
		b.WriteString("</p>\r\n--AA--\r\n")
		textBytes = 2 * len(body)
	case 6, 7: // 20 % pdf attachment (1-3 MB)
		kind = "pdf"
		n := 1<<20 + rng.Intn(2<<20)
		b.WriteString("Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/plain\r\n\r\nquarterly report attached\r\n")
		if i%50 == 0 {
			b.WriteString("corpus token: zebraTAIL\r\n")
		}
		b.WriteString(attach("application/pdf", n))
		b.WriteString("--BB--\r\n")
		textBytes = 32
	case 8: // 10 % image attachment (0.5-2 MB)
		kind = "image"
		n := 1<<19 + rng.Intn(3<<19)
		b.WriteString("Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/plain\r\n\r\nphoto attached\r\n")
		if i%50 == 0 {
			b.WriteString("corpus token: zebraTAIL\r\n")
		}
		b.WriteString(attach("image/jpeg", n))
		b.WriteString("--BB--\r\n")
		textBytes = 16
	case 9: // 10 % calendar (inline ICS, 30 % with pdf attach) or big zip
		if rng.Intn(10) < 6 {
			kind = "calendar"
			b.WriteString("Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Quarterly Sync\r\nDTSTART:20260101T100000Z\r\n")
			if i%50 == 0 {
				b.WriteString("DESCRIPTION:corpus token zebraTAIL\r\n")
			}
			b.WriteString("END:VEVENT\r\nEND:VCALENDAR\r\n")
			if rng.Intn(10) < 3 {
				b.WriteString(attach("application/pdf", 1<<20))
			}
			b.WriteString("--BB--\r\n")
			textBytes = 128
		} else {
			kind = "bigzip"
			n := (8 + rng.Intn(52)) << 20
			b.WriteString("Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/plain\r\n\r\narchive attached\r\n")
			if i%50 == 0 {
				b.WriteString("corpus token: zebraTAIL\r\n")
			}
			b.WriteString(attach("application/zip", n))
			b.WriteString("--BB--\r\n")
			textBytes = 20
		}
	}
	// NOTE: the ground-truth needle must live INSIDE a text/* MIME part —
	// bytes after the final MIME boundary (RFC epilogue) are not indexed by
	// any MIME parser, only reachable via `search --raw`.
	return []byte(b.String()), textBytes, kind
}

func TestScaleCorpus(t *testing.T) {
	targetMB := 0
	if v := os.Getenv("CEA_SCALE_MB"); v != "" {
		fmt.Sscanf(v, "%d", &targetMB)
	}
	if targetMB <= 0 {
		t.Skip("set CEA_SCALE_MB=<megabytes> to run the scale harness")
	}
	dir := os.Getenv("CEA_SCALE_DIR")
	if dir == "" {
		dir = "/tmp/cea-scale"
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	archiveDir := filepath.Join(dir, "archive")
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.txt")
	if err := writeNewKey(keyPath); err != nil {
		t.Fatal(err)
	}
	id, err := loadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	arc := newArchive(archiveDir, id)

	rng := rand.New(rand.NewSource(42))
	type entry struct {
		Kind string `json:"kind"`
		Size int    `json:"size"`
		SHA  string `json:"sha256"`
	}
	manifest := map[string]entry{}
	total := 0
	target := targetMB << 20
	start := time.Now()
	for i := 0; total < target; i++ {
		raw, _, kind := scaleMail(rng, i)
		ok, err := arc.put("scale", raw)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			continue
		}
		sum := sha256.Sum256(raw)
		name := blobName("scale", raw)
		manifest[name] = entry{Kind: kind, Size: len(raw), SHA: fmt.Sprintf("%x", sum)}
		total += len(raw)
		if i%500 == 0 {
			fmt.Printf("  %d mails, %.1f MB (%.0f MB/s)\n", i+1, float64(total)/(1<<20), float64(total)/(1<<20)/time.Since(start).Seconds())
		}
	}
	mj, _ := json.MarshalIndent(manifest, "", " ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), mj, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf("archive_dir = %q\nkey_file = %q\nstate_file = %q\n", archiveDir, keyPath, filepath.Join(dir, "state.json"))
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	nBlobs, _ := arc.blobs()
	fmt.Printf("SCALE CORPUS READY: %d mails, %.1f MB in %s (generation %s)\n", len(nBlobs), float64(total)/(1<<20), dir, time.Since(start).Round(time.Second))
}
