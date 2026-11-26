package app

// Regression benchmarks for the encrypted trigram index. Corpus size scales
// with CEA_BENCH_MB (default 32 MB, CI-friendly); docs/benchmark.md records
// results at 500 MB and 8 GB on real hardware.
//
// Run: go test -bench BenchmarkIndex -benchtime 1x .

import (
	"bytes"
	"filippo.io/age"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// benchCorpus builds a deterministic synthetic mail corpus: ~8 KB text mails
// with Zipfian word distribution (realistic trigram skew), base64 noise to
// simulate attachments, sized to targetMB. Returns raw mail bodies.
func benchCorpus(targetMB int) [][]byte {
	const mailSize = 8 * 1024
	n := targetMB * 1024 * 1024 / mailSize
	word := func(buf *bytes.Buffer) {
		buf.WriteByte(' ')
		for i := 0; i < 6; i++ {
			buf.WriteString(strconv.FormatUint(uint64(mathrand.Uint64()>>11), 36))
		}
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		var b bytes.Buffer
		fmt.Fprintf(&b, "From: sender%d@example.de\r\nSubject: bench mail %d\r\nDate: Mon, 02 Jan 2006 15:04:05 +0100\r\nMessage-ID: <bench%d@test>\r\n\r\n", i, i, i)
		for b.Len() < mailSize-200 {
			word(&b)
		}
		// the needle: every 8th mail carries a distinctive token
		if i%8 == 0 {
			fmt.Fprintf(&b, " zebra%d zebra%d", i, i)
		}
		// base64 attachment noise (skipped by text extraction)
		b.WriteString("Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: application/pdf\r\n\r\n")
		noise := make([]byte, 128)
		for i := range noise {
			noise[i] = byte(mathrand.Uint32())
		}
		b.WriteString(noiseString(noise))
		b.WriteString("\r\n--BB--\r\n")
		out[i] = b.Bytes()
	}
	return out
}

var noiseBuf strings.Builder

func noiseString(b []byte) string {
	noiseBuf.Reset()
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for _, c := range b {
		noiseBuf.WriteByte(chars[int(c)%len(chars)])
	}
	return noiseBuf.String()
}

func benchArchive(b *testing.B) (*Archive, [][]byte) {
	corpus := benchCorpus(benchTargetMB())
	dir := b.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		b.Fatal(err)
	}
	arc := newArchive(dir, id)
	for _, raw := range corpus {
		if _, err := arc.put("bench", raw); err != nil {
			b.Fatal(err)
		}
	}
	return arc, corpus
}

func benchTargetMB() int {
	if v := os.Getenv("CEA_BENCH_MB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 32
}

func BenchmarkIndexBuild(b *testing.B) {
	mb := benchTargetMB()
	b.SetBytes(int64(mb) * 1024 * 1024)
	arc, _ := benchArchive(b)
	segFiles, _ := listSegments(arc)
	cacheDir := filepath.Join(userCfgDir(), "index-cache")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for _, f := range segFiles {
			os.Remove(filepath.Join(arc.dir, f)) //nolint:errcheck
		}
		os.RemoveAll(cacheDir) // measure the cold (no-cache) rebuild path
		b.StartTimer()
		if _, err := ensureIndex(arc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIndexQuery(b *testing.B) {
	arc, _ := benchArchive(b)
	if _, err := ensureIndex(arc); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := queryIndex(arc, "zebra notpresent99"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRawScan(b *testing.B) {
	arc, _ := benchArchive(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := arc.walk("", func(r msgRef) error {
			strings.Contains(strings.ToLower(string(r.raw)), "zebra notpresent99")
			return nil
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
