package app

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"filippo.io/age"
)

// TestMain isolates the user-config dir for the whole test binary: the
// index plaintext cache lives under userCfgDir(), and tests must never
// touch the real ~/.config. Individual tests can still t.Setenv HOME.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "cea-test-config")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Setenv("HOME", tmp)
	os.Setenv("XDG_CONFIG_HOME", tmp)
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

// ---- segment format ----

func mkTestSegment(names ...string) *idxSegment {
	sort.Strings(names)
	s := &idxSegment{covHash: coverageHash(names), blobs: names, tri: map[[3]byte][]uint32{}}
	for i := range names {
		text := searchableText([]byte("Subject: mail " + names[i] + "\r\n\r\nalpha beta gamma alpha"))
		for j := 0; j+3 <= len(text); j++ {
			var key [3]byte
			copy(key[:], text[j:j+3])
			s.tri[key] = append(s.tri[key], uint32(i))
		}
	}
	for k, list := range s.tri {
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
		s.tri[k] = dedupSorted(list)
	}
	return s
}

func TestSegmentRoundTrip(t *testing.T) {
	s := mkTestSegment("acc_aaa", "acc_bbb", "acc_ccc")
	back, err := unmarshalSegment(s.marshal())
	if err != nil {
		t.Fatal(err)
	}
	if s.covHash != back.covHash || !equalStrings(s.blobs, back.blobs) {
		t.Fatalf("round trip mismatch: %v vs %v", s.blobs, back.blobs)
	}
	if len(s.tri) != len(back.tri) {
		t.Fatalf("trigram count %d vs %d", len(s.tri), len(back.tri))
	}
	for k, list := range s.tri {
		if !equalU32(list, back.tri[k]) {
			t.Fatalf("postings mismatch for %q", k)
		}
	}
}

func TestSegmentDeterministic(t *testing.T) {
	a := mkTestSegment("acc_aaa", "acc_bbb", "acc_ccc")
	b := mkTestSegment("acc_ccc", "acc_aaa", "acc_bbb") // different input order
	if !bytes.Equal(a.marshal(), b.marshal()) {
		t.Fatal("segment bytes depend on input order")
	}
	if segmentName(a.marshal()) != segmentName(b.marshal()) {
		t.Fatal("content-addressed names differ for identical content")
	}
	// coverage hash must track the blob list: mutating blobs must invalidate
	bad := mkTestSegment("acc_aaa")
	bad.blobs = append(bad.blobs, "acc_extra")
	if _, err := unmarshalSegment(bad.marshal()); err == nil {
		t.Fatal("coverage hash mismatch must be detected")
	}
}

func TestUnmarshalSegmentGarbage(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("XXXXXXX"), []byte(idxMagic), []byte(idxMagic + "\x00\xff\xff")} {
		if _, err := unmarshalSegment(in); err == nil {
			t.Fatalf("garbage %q accepted", in)
		}
	}
}

// ---- searchableText: MIME extraction semantics ----

func TestSearchableTextDecodesAndFolds(t *testing.T) {
	raw := []byte("From: a@b.c\r\nSubject: \xc3\x9cber Invoice\r\n" +
		"Content-Type: multipart/mixed; boundary=BB\r\n\r\n" +
		"--BB\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte("Quarterly-Report attached")) + "\r\n" +
		"--BB\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		"plain=20body with\r\ncontinuation\r\n" +
		"--BB\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		"JVBERi0xLjcgSGVsbG8gUERGIGNvbnRlbnQ=\r\n" +
		"--BB--\r\n")
	text := string(searchableText(raw))
	for _, want := range []string{"über invoice", "quarterly-report attached", "plain body", "continuation"} {
		if !strings.Contains(text, want) {
			t.Errorf("extracted text missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "hello pdf content") || strings.Contains(text, "JVBERi0x") {
		t.Error("binary attachment content must not leak into the index text")
	}
	if strings.ContainsRune(text, '\r') {
		t.Error("CR must be stripped (folding would break substring matches)")
	}
}

func TestSearchableTextDegradations(t *testing.T) {
	// no header/body split: everything is treated as text
	if got := searchableText([]byte("Just raw text no headers")); string(got) != "just raw text no headers" {
		t.Fatalf("no-split fallback: %q", got)
	}
	// unparseable body after headers: raw body bytes included verbatim
	raw := []byte("Subject: weird\r\n\r\n\x00\x01\x02 garbage bytes")
	if !strings.Contains(string(searchableText(raw)), "garbage bytes") {
		t.Fatal("unparseable body must degrade to raw inclusion")
	}
}

// ---- end-to-end index lifecycle on a real archive ----

func TestIndexEndToEnd(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	for _, body := range []string{
		"Subject: invoice one\r\n\r\nplease pay alpha invoice",
		"Subject: meeting\r\n\r\nbeta agenda attached",
		"Subject: report\r\n\r\nalpha-beta gamma summary",
	} {
		if _, err := env.arc.put("acc", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	cands, err := queryIndex(env.arc, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 2 {
		t.Fatalf("query alpha: got %d candidates, want 2: %v", len(cands), cands)
	}
	cands, err = queryIndex(env.arc, "zzz-no")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 0 {
		t.Fatalf("query zzz-no returned %v", cands)
	}
	if _, err := queryIndex(env.arc, "ab"); err != ErrShortTerm {
		t.Fatalf("short term: got %v, want ErrShortTerm", err)
	}
}

func TestIndexVerificationNoFalsePositives(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	// "abcd" spans trigrams abc + bcd scattered across the mail -> index
	// candidate without real substring match; verification must reject it
	for _, body := range []string{
		"Subject: a\r\n\r\nabc and xyz and bcd scattered here",
		"Subject: b\r\n\r\nreal abcd occurrence",
	} {
		if _, err := env.arc.put("acc", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	cands, err := queryIndex(env.arc, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) < 1 {
		t.Fatal("expected at least the true match as candidate")
	}
	matches := 0
	for _, name := range cands {
		raw, err := env.arc.get(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(searchableText(raw)), "abcd") {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("verification found %d real matches, want 1 (candidates: %v)", matches, cands)
	}
}

func TestIndexIncremental(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha first")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	segs1, _ := listSegments(env.arc)
	if len(segs1) != 1 {
		t.Fatalf("want 1 segment, got %d", len(segs1))
	}
	// second ensureIndex without changes: fast path, no new segment
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	if segs2, _ := listSegments(env.arc); len(segs2) != 1 {
		t.Fatalf("no-op reindex added segments: %v", segs2)
	}
	// new blob -> exactly one new segment covering only the new blob
	if _, err := env.arc.put("acc", []byte("Subject: two\r\n\r\nbeta second")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	if segs3, _ := listSegments(env.arc); len(segs3) != 2 {
		t.Fatalf("incremental should add exactly 1 segment, got %d", len(segs3))
	}
	cands, err := queryIndex(env.arc, "beta second")
	if err != nil || len(cands) != 1 {
		t.Fatalf("cross-segment query failed: %v (%v)", cands, err)
	}
}

func TestIndexCompaction(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	for i := 0; i < idxMaxSegments+1; i++ {
		if _, err := env.arc.put("acc", []byte(fmt.Sprintf("Subject: m%d\r\n\r\ncontent token%d", i, i))); err != nil {
			t.Fatal(err)
		}
		if _, err := ensureIndex(env.arc); err != nil {
			t.Fatal(err)
		}
	}
	segs, _ := listSegments(env.arc)
	if len(segs) != 1 {
		t.Fatalf("compaction to 1 segment failed: %d segments", len(segs))
	}
	for _, tok := range []string{"token0", "token7", "token16"} {
		cands, err := queryIndex(env.arc, tok)
		if err != nil || len(cands) != 1 {
			t.Fatalf("query %s after compaction: %v (%v)", tok, cands, err)
		}
	}
}

func TestIndexSelfHeal(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha original")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	segs, _ := listSegments(env.arc)
	if err := os.WriteFile(filepath.Join(env.arc.dir, segs[0]), []byte("garbage not even encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatalf("self-heal failed: %v", err)
	}
	if segs, _ = listSegments(env.arc); len(segs) != 1 {
		t.Fatalf("after heal want 1 segment, got %d", len(segs))
	}
	cands, err := queryIndex(env.arc, "alpha original")
	if err != nil || len(cands) != 1 {
		t.Fatalf("query after self-heal: %v (%v)", cands, err)
	}
}

func TestIndexCache(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha cached")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	segs, _ := listSegments(env.arc)
	hash := strings.TrimSuffix(strings.TrimPrefix(segs[0], ".idx-"), ".age")
	cache := filepath.Join(userCfgDir(), "index-cache", hash)
	// the cache is written on first load: force one via a query
	if cands, err := queryIndex(env.arc, "alpha cached"); err != nil || len(cands) != 1 {
		t.Fatalf("pre-cache query: %v (%v)", cands, err)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("plaintext cache not written: %v", err)
	}
	// corrupted cache falls back to the encrypted segment
	if err := os.WriteFile(cache, []byte("CEAIDX1rubbish"), 0o600); err != nil {
		t.Fatal(err)
	}
	cands, err := queryIndex(env.arc, "alpha cached")
	if err != nil || len(cands) != 1 {
		t.Fatalf("query with corrupt cache: %v (%v)", cands, err)
	}
	// pruning removes orphaned cache entries
	if err := os.Remove(filepath.Join(env.arc.dir, segs[0])); err != nil {
		t.Fatal(err)
	}
	pruneIndexCache(env.arc)
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatal("orphaned cache entry not pruned")
	}
}

func TestBlobsSkipIndexFiles(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha real mail")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	blobs, err := env.arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 1 {
		t.Fatalf("index segment leaked into blobs(): %v", blobs)
	}
	out := captureStdout(t, func() {
		if code := run([]string{"verify", "-config", env.cfgPath}); code != 0 {
			t.Errorf("verify exit %d", code)
		}
	})
	if !strings.Contains(out, "1 ok, 0 failed") {
		t.Fatalf("verify output with index present: %q", out)
	}
}

// ---- command-level behavior ----

func TestCmdSearchIndexedVsRaw(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	// term in a binary attachment (8bit CTE): invisible to the text index,
	// visible to the raw scan
	raw := []byte("Subject: mixed\r\n" +
		"Content-Type: multipart/mixed; boundary=XX\r\n\r\n" +
		"--XX\r\nContent-Type: text/plain\r\n\r\nplain alpha body\r\n" +
		"--XX\r\nContent-Type: application/octet-stream\r\n\r\nNEEDLE-in-binary\r\n" +
		"--XX--\r\n")
	if _, err := env.arc.put("acc", raw); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if code := run([]string{"search", "-config", env.cfgPath, "alpha"}); code != 0 {
			t.Errorf("indexed search exit %d", code)
		}
	})
	if !strings.Contains(out, "mixed") || !strings.Contains(out, "1 match(es)") {
		t.Fatalf("indexed search output: %q", out)
	}
	out = captureStdout(t, func() {
		if code := run([]string{"search", "-config", env.cfgPath, "-raw", "NEEDLE"}); code != 0 {
			t.Errorf("raw search exit %d", code)
		}
	})
	if !strings.Contains(out, "1 match(es)") {
		t.Fatalf("raw search must match the 8bit attachment bytes: %q", out)
	}
}

func TestCmdSearchIndexedFallsBackWhenIndexFails(t *testing.T) {
	needPosixPerms(t)
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha fallback")); err != nil {
		t.Fatal(err)
	}
	// make the archive dir unwritable -> ensureIndex cannot create segments
	if err := os.Chmod(env.arc.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(env.arc.dir, 0o700) }) //nolint:errcheck
	var out string
	stdcombined := captureStderr(t, func() {
		out = captureStdout(t, func() {
			if code := run([]string{"search", "-config", env.cfgPath, "alpha"}); code != 0 {
				t.Errorf("search exit %d", code)
			}
		})
	})
	if !strings.Contains(stdcombined, "falling back to raw scan") {
		t.Errorf("fallback note expected on stderr, got %q", stdcombined)
	}
	if !strings.Contains(out, "1 match(es)") {
		t.Fatalf("search must fall back to raw scan when index build fails: %q", out)
	}
}

func TestCmdIndexReports(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if code := run([]string{"index", "-config", env.cfgPath}); code != 0 {
			t.Errorf("index exit %d", code)
		}
	})
	if !strings.Contains(out, "index: 1 blob(s) covered, 1 segment(s)") {
		t.Fatalf("index output: %q", out)
	}
}

func TestCmdSearchAccountFilterIndexed(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	for _, acc := range []string{"real", "other"} {
		if _, err := env.arc.put(acc, []byte("Subject: x\r\n\r\nfindme "+acc)); err != nil {
			t.Fatal(err)
		}
	}
	out := captureStdout(t, func() {
		if code := run([]string{"search", "-config", env.cfgPath, "-account", "REAL", "findme"}); code != 0 {
			t.Errorf("search exit %d", code)
		}
	})
	if !strings.Contains(out, "real") || strings.Contains(out, "other") {
		t.Fatalf("account filter broken: %q", out)
	}
}

func TestSyncWritesIndex(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	env := syncTestEnv(t, port, "stress", []string{"INBOX"})
	seedMail(t, u, "INBOX", "Subject: synced\r\n\r\nindexed after sync\r\n")
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit %d", code)
	}
	segs, err := listSegments(env.arc)
	if err != nil || len(segs) != 1 {
		t.Fatalf("sync must leave exactly 1 segment, got %v (%v)", segs, err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RFC epilogue (bytes after the final MIME boundary) is invisible to every
// MIME parser — the index only covers structured text; `--raw` still finds
// epilogue bytes. This pins that documented divergence.
func TestSearchableTextIgnoresEpilogue(t *testing.T) {
	raw := []byte("Subject: mixed\r\n" +
		"Content-Type: multipart/mixed; boundary=XX\r\n\r\n" +
		"--XX\r\nContent-Type: text/plain\r\n\r\nplain alpha body\r\n" +
		"--XX--\r\nEPILOGUE-NOT-INDEXED\r\n")
	text := string(searchableText(raw))
	if !strings.Contains(text, "plain alpha body") {
		t.Fatal("structured text missing")
	}
	if strings.Contains(text, "EPILOGUE-NOT-INDEXED") {
		t.Fatal("epilogue must not leak into the indexed text")
	}
	if !strings.Contains(strings.ToLower(string(raw)), "epilogue-not-indexed") {
		t.Fatal("raw bytes still carry the epilogue (for --raw)")
	}
}

// ---- hostile / corrupt segment inputs (found via FuzzSegmentParse; pinned
// here as explicit unit tests so the parser contract is documented) ----

func TestSegmentParserRejections(t *testing.T) {
	good := mkTestSegment("acc_aaa", "acc_bbb").marshal()

	// helper: craft a valid prefix then splice hostile bytes
	build := func(afterBlobs []byte) []byte {
		buf := bytes.NewBuffer(nil)
		buf.WriteString(idxMagic)
		cov := coverageHash([]string{"acc_aaa", "acc_bbb"})
		buf.Write(cov[:])
		putUvarint(buf, 2)
		putUvarint(buf, 7)
		buf.WriteString("acc_aaa")
		putUvarint(buf, 7)
		buf.WriteString("acc_bbb")
		buf.Write(afterBlobs)
		return buf.Bytes()
	}
	craft := func(body []byte) []byte {
		buf := bytes.NewBuffer(nil)
		buf.WriteString(idxMagic)
		cov := coverageHash([]string{"acc_aaa"})
		buf.Write(cov[:])
		putUvarint(buf, 1)
		buf.WriteString("acc_aaa")
		buf.Write(body)
		return buf.Bytes()
	}
	overlong := func(vals ...uint64) []byte { // varints encoded non-minimally
		buf := bytes.NewBuffer(nil)
		for _, v := range vals {
			buf.WriteByte(byte(v&0x7f | 0x80)) // continuation bit set
			buf.WriteByte(byte(v >> 7))        // zero terminator
		}
		return buf.Bytes()
	}

	cases := map[string][]byte{
		"trailing byte after body":   append(append([]byte{}, good...), 0x00),
		"name length beyond cap":     craft(func() []byte { b := bytes.NewBuffer(nil); putUvarint(b, idxMaxNameLen+1); return b.Bytes() }()),
		"postings exceed blob count": craft([]byte{0x61, 0x61, 0x61, 0x05, 0x00, 0x00}), // 1-blob segment, posting count 5
		"non-canonical varint":       craft(append([]byte{0x61, 0x61, 0x61, 0x01}, overlong(0)...)),
		"varint overflow":            craft(bytes.Repeat([]byte{0xff}, 11)),
		"keys not ascending":         build([]byte{0x02, 'z', 'z', 'z', 0x00, 'a', 'a', 'a', 0x00}),
		"duplicate keys":             build([]byte{0x02, 'a', 'a', 'a', 0x00, 'a', 'a', 'a', 0x00}),
		"posting index out of range": build([]byte{0x01, 'a', 'a', 'a', 0x01, 0x7f}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := unmarshalSegment(data); err == nil {
				t.Fatalf("hostile input accepted:\n%x", data)
			}
		})
	}
	// sanity: the crafted-blob-list prefix with valid postings still parses
	if _, err := unmarshalSegment(build([]byte{0x01, 'a', 'a', 'a', 0x01, 0x00})); err != nil {
		t.Fatalf("valid crafted segment rejected: %v", err)
	}
}

// ---- fault injection: index write failures must propagate ----

func TestWriteSegmentFaultInjection(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	env.arc.newWriter = func(io.Writer, ...age.Recipient) (io.WriteCloser, error) {
		return nil, errors.New("disk full injected")
	}
	if _, err := ensureIndex(env.arc); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("write fault not propagated: %v", err)
	}
}

func TestSegmentCoverageHashPeek(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	segs, _ := listSegments(env.arc)
	// valid peek
	h, err := segmentCoverageHash(env.arc, segs[0])
	if err != nil {
		t.Fatal(err)
	}
	blobs, _ := env.arc.blobs()
	if want := coverageHash([]string{blobs[0].name}); h != want {
		t.Fatal("peeked coverage hash mismatch")
	}
	// missing file
	if _, err := segmentCoverageHash(env.arc, ".idx-doesnotexist.age"); err == nil {
		t.Fatal("missing segment accepted")
	}
	// corrupt (not valid age) file
	corrupt := ".idx-corrupt.age"
	if err := os.WriteFile(filepath.Join(env.arc.dir, corrupt), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := segmentCoverageHash(env.arc, corrupt); err == nil {
		t.Fatal("corrupt segment accepted")
	}
	// valid age but not a segment (wrong magic): encrypt short junk
	junk, err := encryptTestBytes(env.arc.id, []byte("short but encrypted"))
	if err != nil {
		t.Fatal(err)
	}
	badMagic := ".idx-badmagic.age"
	if err := os.WriteFile(filepath.Join(env.arc.dir, badMagic), junk, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := segmentCoverageHash(env.arc, badMagic); err == nil {
		t.Fatal("wrong-magic segment accepted")
	}
}

// ---- MIME extraction edge cases ----

func TestAppendEntityNestedRFC822(t *testing.T) {
	inner := "Subject: inner nested\r\n\r\ninner body findme-inner\r\n"
	raw := []byte("Subject: outer\r\n" +
		"Content-Type: multipart/mixed; boundary=XX\r\n\r\n" +
		"--XX\r\nContent-Type: text/plain\r\n\r\nouter body\r\n" +
		"--XX\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte(inner)) + "\r\n" +
		"--XX--\r\n")
	text := string(searchableText(raw))
	for _, want := range []string{"outer body", "inner nested", "findme-inner"} {
		if !strings.Contains(text, want) {
			t.Errorf("nested rfc822 text missing %q:\n%s", want, text)
		}
	}
}

func TestAppendEntityUnknownCTEAndBoundaryless(t *testing.T) {
	// unknown CTE degrades to passthrough bytes
	raw := []byte("Subject: x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: x-unknown\r\n\r\npassthrough body\r\n")
	if !strings.Contains(string(searchableText(raw)), "passthrough body") {
		t.Fatal("unknown CTE must degrade to raw passthrough")
	}
	// multipart without boundary parameter: nothing indexable from body
	raw = []byte("Subject: y\r\nContent-Type: multipart/mixed\r\n\r\nbody never reached\r\n")
	if strings.Contains(string(searchableText(raw)), "never reached") {
		t.Fatal("boundary-less multipart must not be parsed as parts")
	}
}

// ---- resilience: vanished blobs between index build and query ----

func TestCmdSearchVanishedBlobSkipped(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	m1 := "Subject: one\r\n\r\nfindme alpha uniqueone"
	m2 := "Subject: two\r\n\r\nfindme beta uniquetwo"
	m3 := "Subject: three\r\n\r\nfindme gamma uniquethree"
	for _, m := range []string{m1, m2, m3} {
		if _, err := env.arc.put("acc", []byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	// the "uniquetwo" blob vanishes after indexing (e.g. deleted externally)
	victim := blobName("acc", []byte(m2))
	if err := os.Remove(filepath.Join(env.arc.dir, victim)); err != nil {
		t.Fatal(err)
	}
	// the surviving blob is still found — stale coverage is harmless
	out := captureStdout(t, func() {
		if code := run([]string{"search", "-config", env.cfgPath, "uniquethree"}); code != 0 {
			t.Errorf("search exit %d", code)
		}
	})
	if !strings.Contains(out, "1 match(es)") {
		t.Fatalf("search must skip vanished blobs silently: %q", out)
	}
	// and the vanished mail's own term correctly finds nothing, without error
	out = captureStdout(t, func() {
		if code := run([]string{"search", "-config", env.cfgPath, "uniquetwo"}); code != 0 {
			t.Errorf("search exit %d", code)
		}
	})
	if !strings.Contains(out, "0 match(es)") {
		t.Fatalf("vanished mail must yield 0 matches, got %q", out)
	}
}

// encryptTestBytes encrypts to the archive identity using the age API
// directly (bypasses the Archive seam).
func encryptTestBytes(id *age.X25519Identity, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- remaining self-heal / error-path coverage ----

// queryIndex must fail (→ raw fallback) when no segment exists, and
// searchIndexed must return ErrShortTerm for short terms.
func TestQueryIndexErrors(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := queryIndex(env.arc, "alpha"); err == nil {
		t.Fatal("query without any segment must error (triggers raw fallback)")
	}
	if _, err := queryIndex(env.arc, "ab"); !errors.Is(err, ErrShortTerm) {
		t.Fatalf("want ErrShortTerm, got %v", err)
	}
}

// compactIndex with a >2-segment input: postings must be remapped correctly
// across three source segments (oldOrder/newIdx path).
func TestIndexCompactionThreeSegments(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	terms := []string{"alphazulu", "bravoyankee", "xraykilos"}
	for _, term := range terms { // one sync+ensure per blob → one segment each
		if _, err := env.arc.put("acc", []byte("Subject: m\r\n\r\n"+term)); err != nil {
			t.Fatal(err)
		}
		if _, err := ensureIndex(env.arc); err != nil {
			t.Fatal(err)
		}
	}
	if segs, _ := listSegments(env.arc); len(segs) != 3 {
		t.Fatalf("want 3 segments, have %d", len(segs))
	}
	segs, _ := listSegments(env.arc)
	if err := compactIndex(env.arc, segs); err != nil {
		t.Fatal(err)
	}
	if segs2, _ := listSegments(env.arc); len(segs2) != 1 {
		t.Fatalf("compaction left %d segments", len(segs2))
	}
	for _, term := range terms { // remapped postings must still resolve
		cands, err := queryIndex(env.arc, term)
		if err != nil || len(cands) != 1 {
			t.Errorf("post-compaction query %q: %v (%v)", term, cands, err)
		}
	}
}

// a corrupt plaintext cache entry must be dropped and re-fetched from the
// encrypted segment (both sides of the cache lifecycle).
func TestIndexCacheCorruptDropped(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha cached")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	segs, _ := listSegments(env.arc)
	hash := strings.TrimSuffix(strings.TrimPrefix(segs[0], ".idx-"), ".age")
	cache := filepath.Join(userCfgDir(), "index-cache", hash)
	if cands, err := queryIndex(env.arc, "alpha cached"); err != nil || len(cands) != 1 {
		t.Fatalf("query: %v (%v)", cands, err)
	}
	// corrupt the cache: loadSegment must detect the damage (truncated
	// segment fails coverage verification) and re-read from the .age file
	good, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, good[:len(good)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if cands, err := queryIndex(env.arc, "alpha cached"); err != nil || len(cands) != 1 {
		t.Fatalf("query with corrupt cache: %v (%v)", cands, err)
	}
	// cache must have been repaired
	if fixed, err := os.ReadFile(cache); err != nil || !bytes.Equal(fixed, good) {
		t.Fatalf("cache not repaired after corruption (len %d)", len(fixed))
	}
}

// getUvarint: canonical gate and overflow paths, exercised directly.
func TestGetUvarintRejects(t *testing.T) {
	overlong := []byte{0x80, 0x00} // zero, encoded non-minimally
	if v, err := getUvarint(bytes.NewReader(overlong)); err == nil {
		t.Fatalf("overlong varint accepted, value %d", v)
	}
	overflow := bytes.Repeat([]byte{0xff}, 11) // would need 10 bytes max
	if _, err := getUvarint(bytes.NewReader(overflow)); err == nil {
		t.Fatal("overflow varint accepted")
	}
	if v, err := getUvarint(bytes.NewReader([]byte{0x80, 0x02})); err != nil || v != 256 {
		t.Fatalf("valid multi-byte varint: %d %v", v, err)
	}
}

// ---- coverage round: parser contract, fault seams, index semantics ----

// Every malformed-segment class the parser rejects, crafted at the byte level,
// with the rejection reason asserted (contract, not just any error).
func TestSegmentParserRejectionsFull(t *testing.T) {
	quietLog()
	goodCov := coverageHash([]string{"acc_aaa"})
	// base writes magic+covHash; build continues with names and returns the
	// buffer for case-specific tails
	names := func(b *bytes.Buffer, ns ...string) {
		putUvarint(b, uint64(len(ns)))
		for _, n := range ns {
			putUvarint(b, uint64(len(n)))
			b.WriteString(n)
		}
	}
	trigram := func(b *bytes.Buffer, key [3]byte, postings ...uint32) {
		b.Write(key[:])
		sort.Slice(postings, func(i, j int) bool { return postings[i] < postings[j] })
		putUvarint(b, uint64(len(postings)))
		prev := uint32(0)
		for i, p := range postings {
			if i > 0 {
				putUvarint(b, uint64(p-postings[i-1]))
			} else {
				prev = p
				putUvarint(b, uint64(p))
			}
		}
		_ = prev
	}
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"wrong magic", append([]byte("NOPE1"), func() []byte {
			var b bytes.Buffer
			b.Write(goodCov[:])
			names(&b, "acc_aaa")
			trigram(&b, [3]byte{'a', 'b', 'c'}, 0)
			return b.Bytes()
		}()...), "bad index segment magic"},
		{"blob count missing", append([]byte(idxMagic), goodCov[:]...), "blob count"},
		{"name length missing", append([]byte(idxMagic), append(goodCov[:], 0x01)...), "blob name len"},
		{"name length overruns buffer", func() []byte {
			var b bytes.Buffer
			b.Write([]byte(idxMagic))
			b.Write(goodCov[:])
			putUvarint(&b, 1)
			putUvarint(&b, 0x7f) // promises 127-byte name, none follows
			return b.Bytes()
		}(), "EOF"},
		{"name too long", func() []byte {
			var b bytes.Buffer
			b.Write([]byte(idxMagic))
			b.Write(goodCov[:])
			names(&b, strings.Repeat("a", idxMaxNameLen+1))
			return b.Bytes()
		}(), "name too long"},
		{"trigram count missing", func() []byte {
			var b bytes.Buffer
			b.Write([]byte(idxMagic))
			b.Write(goodCov[:])
			names(&b, "acc_aaa")
			return b.Bytes()
		}(), "trigram count"},
		{"trigram key truncated", func() []byte {
			var b bytes.Buffer
			b.Write([]byte(idxMagic))
			b.Write(goodCov[:])
			names(&b, "acc_aaa")
			putUvarint(&b, 1)
			b.WriteString("ab") // key promises 3 bytes, body ends
			return b.Bytes()
		}(), "EOF"},
		{"posting count missing", func() []byte {
			var b bytes.Buffer
			b.Write([]byte(idxMagic))
			b.Write(goodCov[:])
			names(&b, "acc_aaa")
			putUvarint(&b, 1)
			b.WriteString("abc") // key complete, no posting count
			return b.Bytes()
		}(), "posting len"},
		{"posting list exceeds blob count", func() []byte {
			var b bytes.Buffer
			b.Write([]byte(idxMagic))
			b.Write(goodCov[:])
			names(&b, "acc_aaa")
			putUvarint(&b, 1)
			b.WriteString("abc")
			putUvarint(&b, 5) // claims 5 postings, only 1 blob exists
			putUvarint(&b, 0)
			return b.Bytes()
		}(), "exceeds blob count"},
		{"postings not strictly ascending", func() []byte {
			var b bytes.Buffer
			cov := coverageHash([]string{"acc_aaa", "acc_bbb"}) // 2 blobs: only way to get a duplicate index past the blob-count check
			b.Write([]byte(idxMagic))
			b.Write(cov[:])
			names(&b, "acc_aaa", "acc_bbb")
			putUvarint(&b, 1)
			b.WriteString("abc")
			putUvarint(&b, 2) // deltas 1,0 → postings [1,1] — duplicate index
			putUvarint(&b, 1)
			putUvarint(&b, 0)
			return b.Bytes()
		}(), "not strictly ascending"},
		{"trailing garbage", func() []byte {
			var b bytes.Buffer
			b.Write([]byte(idxMagic))
			b.Write(goodCov[:])
			names(&b, "acc_aaa")
			putUvarint(&b, 1)
			b.WriteString("abc")
			putUvarint(&b, 1)
			putUvarint(&b, 0)
			b.WriteByte(0xff) // valid body, one byte too many
			return b.Bytes()
		}(), "trailing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unmarshalSegment(tc.data)
			if err == nil {
				t.Fatalf("malformed segment (%s) accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong rejection reason: got %q, want %q", err, tc.want)
			}
		})
	}
	// control: the same structure minus the trailing byte parses cleanly
	var ok bytes.Buffer
	ok.Write([]byte(idxMagic))
	ok.Write(goodCov[:])
	names(&ok, "acc_aaa")
	putUvarint(&ok, 1) // trigram count
	trigram(&ok, [3]byte{'a', 'b', 'c'}, 0)
	if _, err := unmarshalSegment(ok.Bytes()); err != nil {
		t.Fatalf("valid crafted segment rejected: %v", err)
	}
}

// getUvarint must reject a varint carrying data past bit 63: a 10-byte
// sequence whose last byte still has the continuation bit overflows exactly
// at the shift-63 guard (the separate "varint too long" check is
// defense-in-depth; see comment in getUvarint).
func TestGetUvarintTooLong(t *testing.T) {
	quietLog()
	tooLong := bytes.Repeat([]byte{0x80}, binary.MaxVarintLen64) // 10 continuing bytes
	if _, err := getUvarint(bytes.NewReader(tooLong)); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("10-byte continuing varint accepted: %v", err)
	}
}

// writeSegment fault injection: Write and Close failures must clean up the
// temp file and propagate.
func TestWriteSegmentWriteAndCloseFault(t *testing.T) {
	skipOnWindows(t, "fault removes an open file — Windows refuses")
	quietLog()
	for _, tc := range []struct {
		name string
		w    io.WriteCloser
		want string
	}{
		{"write fault", &failWriter{}, "write injected"},
		{"close fault", &failCloser{Writer: io.Discard}, "close injected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
				t.Fatal(err)
			}
			env.arc.newWriter = func(io.Writer, ...age.Recipient) (io.WriteCloser, error) {
				return tc.w, nil
			}
			if _, err := ensureIndex(env.arc); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s not propagated: %v", tc.name, err)
			}
			entries, _ := os.ReadDir(env.arc.dir)
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".tmp") {
					t.Fatalf("temp file leaked after %s: %s", tc.name, e.Name())
				}
			}
		})
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write injected") }
func (failWriter) Close() error              { return nil }
func (failWriter) Name() string              { return "fail" }

type failCloser struct{ io.Writer }

func (failCloser) Close() error { return errors.New("close injected") }

// Rename failure: a non-empty directory already occupies the
// content-addressed segment path (e.g. a hostile tenant planting a folder).
// writeSegment is called directly: ensureIndex would self-heal an empty
// obstacle away before the rename ever happens.
func TestWriteSegmentRenameFault(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	mail := []byte("Subject: one\r\n\r\nalpha")
	if _, err := env.arc.put("acc", mail); err != nil {
		t.Fatal(err)
	}
	seg, err := buildSegment(env.arc, []string{blobName("acc", mail)})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(env.arc.dir, segmentName(seg.marshal()))
	if err := os.MkdirAll(filepath.Join(target, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := writeSegment(env.arc, seg); err == nil {
		t.Fatal("rename onto directory accepted")
	} else if _, err := os.Stat(filepath.Join(env.arc.dir, ".idx-d26819c5abaa6e7d76aab88bfeb25f26671d3b1d4cb3997519354e07bfc317cd.age")); err == nil {
		t.Fatal("tmp file leaked after failed rename")
	}
	tmpLeaked := false
	entries, _ := os.ReadDir(env.arc.dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			tmpLeaked = true
		}
	}
	if tmpLeaked {
		t.Fatal("tmp file leaked after failed rename")
	}
	os.RemoveAll(target)
	if _, err := writeSegment(env.arc, seg); err != nil { // retry works
		t.Fatal(err)
	}
}

// segmentCoverageHash must reject a segment whose plaintext lacks the magic.
func TestSegmentCoverageHashBadMagic(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if err := os.MkdirAll(env.arc.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// >39 bytes so the magic check is reached before the short-read EOF
	blob, err := encryptTestBytes(env.arc.id, []byte("NOPE1. definitely not an index segment, padded past the 39-byte header peek"))
	if err != nil {
		t.Fatal(err)
	}
	name := ".idx-deadbeef.age"
	if err := os.WriteFile(filepath.Join(env.arc.dir, name), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := segmentCoverageHash(env.arc, name); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("wrong-magic segment accepted: %v", err)
	}
}

// Compaction sanitizes trigrams with EMPTY posting lists. Real builds never
// produce them, but the canonical format permits them (a hand-crafted valid
// segment can carry trigram -> []), so the merge must drop them instead of
// emitting a postings block no reader can meaningfully intersect.
func TestCompactIndexDropsEmptyPostings(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	mail := []byte("Subject: one\r\n\r\nalphazulu")
	if _, err := env.arc.put("acc", mail); err != nil {
		t.Fatal(err)
	}
	seg := mkTestSegment(blobName("acc", mail))
	seg.tri[[3]byte{'z', 'z', 'z'}] = []uint32{} // canonical-format poison pill
	if _, err := writeSegment(env.arc, seg); err != nil {
		t.Fatal(err)
	}
	segs, _ := listSegments(env.arc)
	if err := compactIndex(env.arc, segs); err != nil {
		t.Fatal(err)
	}
	out, _ := listSegments(env.arc)
	if len(out) != 1 {
		t.Fatalf("compaction left %d segments", len(out))
	}
	merged, err := loadSegment(env.arc, out[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := merged.tri[[3]byte{'z', 'z', 'z'}]; ok {
		t.Fatal("empty posting list survived compaction")
	}
	// mkTestSegment trigrams "alpha beta gamma" — query one of those
	if cands, err := queryIndex(env.arc, "gamma"); err != nil || len(cands) != 1 {
		t.Fatalf("real postings lost in compaction: %v (%v)", cands, err)
	}
}

// Term whose trigrams all exist somewhere but never in one blob: intersect
// empties, query returns zero candidates without error (and searchIndexed
// has nothing to decrypt).
func TestQueryIndexEmptyIntersection(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	for _, m := range []string{
		"Subject: one\r\n\r\nabcde zzz",   // trigrams abc,bcd,cde
		"Subject: two\r\n\r\nxxdefxx zzz", // trigram def
	} {
		if _, err := env.arc.put("acc", []byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	// ONE ensureIndex so both blobs share a segment — queryIndex intersects
	// per segment; two segments would just miss trigrams entirely
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	// "abcdef" needs abc+bcd+cde (blob 1) AND def (blob 2) — no blob has all
	cands, err := queryIndex(env.arc, "abcdef")
	if err != nil || len(cands) != 0 {
		t.Fatalf("partitioned term resolved: %v (%v)", cands, err)
	}
}

// False-positive skip: all trigrams of the term exist in ONE blob (so the
// intersection is non-empty), but the term is not a contiguous substring —
// searchIndexed must verify by decrypting and drop the candidate.
func TestSearchIndexedFalsePositiveSkip(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	// chain overlaps so every trigram of "abcdefgh" occurs, yet the term
	// itself is nowhere contiguous
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nabcdbcdecdefefgfgh zzz")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	n, err := searchIndexed(&cmdEnv{cfg: &Config{ArchiveDir: env.arc.dir}, arc: env.arc}, "abcdefgh")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("false positive counted as match: %d", n)
	}
	// control: a real substring match is found
	if n, err := searchIndexed(&cmdEnv{cfg: &Config{ArchiveDir: env.arc.dir}, arc: env.arc}, "cdecdef"); err != nil || n != 1 {
		t.Fatalf("real substring missed: %d (%v)", n, err)
	}
}

// intersectSorted edge branches: strictly-greater elements on both sides and
// disjoint inputs.
func TestIntersectSortedBranches(t *testing.T) {
	quietLog()
	if got := intersectSorted([]uint32{1, 5, 9}, []uint32{2, 5, 10}); len(got) != 1 || got[0] != 5 {
		t.Fatalf("intersectSorted = %v, want [5]", got)
	}
	if got := intersectSorted([]uint32{1, 2}, []uint32{3, 4}); len(got) != 0 {
		t.Fatalf("disjoint inputs intersect: %v", got)
	}
	if got := intersectSorted(nil, []uint32{1}); len(got) != 0 {
		t.Fatalf("nil input intersect: %v", got)
	}
}

// A blob whose bytes are not parseable as MIME must still contribute its raw
// text to the index (degrade-to-raw branch in appendMailText).
func TestAppendMailTextGarbageBody(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	// header block present but malformed ("no colon" line) → mail.Read fails
	// AFTER the split, body degrades to raw
	if _, err := env.arc.put("acc", []byte("not-a-header\r\n\r\nneedleplain body\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	cands, err := queryIndex(env.arc, "needleplain")
	if err != nil || len(cands) != 1 {
		t.Fatalf("raw-degraded blob not indexed: %v (%v)", cands, err)
	}
}

// quoted-printable bodies must be decoded before trigramming (=XX escapes
// would otherwise hide the text).
func TestIndexedQuotedPrintable(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	mail := "Subject: qp\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nsearchab=6Ce term here\r\n"
	if _, err := env.arc.put("acc", []byte(mail)); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	if cands, err := queryIndex(env.arc, "searchable"); err != nil || len(cands) != 1 {
		t.Fatalf("QP-encoded needle not indexed: %v (%v)", cands, err)
	}
}

// ensureIndex must fail on an unreadable archive dir (blob enumeration).
func TestEnsureIndexUnreadableDir(t *testing.T) {
	needPosixPerms(t)
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(env.arc.dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(env.arc.dir, 0o700) })
	if _, err := ensureIndex(env.arc); err == nil {
		t.Fatal("ensureIndex ignored unreadable archive dir")
	}
}

// queryIndex must fail (raw-scan fallback) on a corrupt segment rather than
// returning bogus candidates.
func TestQueryIndexCorruptSegment(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if err := os.MkdirAll(env.arc.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	blob, err := encryptTestBytes(env.arc.id, []byte("NOPE1. not a segment, padded past the 39-byte header peek for the magic check"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.arc.dir, ".idx-corrupt.age"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := queryIndex(env.arc, "anything"); err == nil {
		t.Fatal("queryIndex accepted corrupt segment")
	}
}

// compactIndex called directly with a corrupt segment must error (self-heal
// already filtered such segments out of ensureIndex's path — this is the
// contract for direct callers).
func TestCompactIndexCorruptSegment(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	if err := os.MkdirAll(env.arc.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	blob, err := encryptTestBytes(env.arc.id, []byte("NOPE1. not a segment, padded past the 39-byte header peek for the magic check"))
	if err != nil {
		t.Fatal(err)
	}
	name := ".idx-corrupt.age"
	if err := os.WriteFile(filepath.Join(env.arc.dir, name), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := compactIndex(env.arc, []string{name}); err == nil {
		t.Fatal("compaction accepted corrupt segment")
	}
}

// When compaction's write fails, the ORIGINAL segments must survive (old
// files are removed only after the merged segment is durable).
func TestCompactionWriteFailureKeepsOriginals(t *testing.T) {
	env := newTestEnv(t)
	quietLog()
	var names []string
	for i := 0; i < 17; i++ { // one more than idxMaxSegments
		mail := []byte("Subject: m" + string(rune('a'+i)) + "\r\n\r\nbody" + string(rune('a'+i)) + "x")
		if _, err := env.arc.put("acc", mail); err != nil {
			t.Fatal(err)
		}
		names = append(names, blobName("acc", mail))
	}
	// write 17 one-blob segments directly: routing them through ensureIndex
	// would auto-compact at the 17th (compaction triggers at >16)
	for _, n := range names {
		if _, err := writeSegment(env.arc, mkTestSegment(n)); err != nil {
			t.Fatal(err)
		}
	}
	if segs, _ := listSegments(env.arc); len(segs) != 17 {
		t.Fatalf("setup: %d segments, want 17", len(segs))
	}
	env.arc.newWriter = func(io.Writer, ...age.Recipient) (io.WriteCloser, error) {
		return nil, errors.New("compaction write injected")
	}
	if _, err := ensureIndex(env.arc); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("compaction failure not propagated: %v", err)
	}
	if segs, _ := listSegments(env.arc); len(segs) != 17 {
		t.Fatalf("originals destroyed on failed compaction: %d left", len(segs))
	}
	// recovery: once the fault clears, compaction succeeds
	env.arc.newWriter = age.Encrypt
	if n, err := ensureIndex(env.arc); err != nil || n != 1 {
		t.Fatalf("recovery compaction: n=%d err=%v", n, err)
	}
}

// pruneIndexCache best-effort: an unreadable cache dir must not fail the
// overall index run.
func TestPruneIndexCacheUnreadableDir(t *testing.T) {
	needPosixPerms(t)
	env := newTestEnv(t)
	quietLog()
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err) // creates the cache dir
	}
	cacheDir := filepath.Join(userCfgDir(), "index-cache")
	if err := os.Chmod(cacheDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cacheDir, 0o700) })
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatalf("prune failure broke ensureIndex: %v", err)
	}
}

// listSegments/post-write plumbing: after a successful segment write, the
// follow-up directory listing must fail the ensureIndex run when the dir
// turns -wx (rename still possible, readdir not). 0333 is the only mode that
// separates the two operations.
func TestEnsureIndexPostWriteListFault(t *testing.T) {
	needPosixPerms(t)
	quietLog()
	env := newTestEnv(t)
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	env.arc.newWriter = func(w io.Writer, r ...age.Recipient) (io.WriteCloser, error) {
		inner, err := age.Encrypt(w, r...)
		if err != nil {
			return nil, err
		}
		return &sideClose{WriteCloser: inner, side: func() {
			os.Chmod(env.arc.dir, 0o333) //nolint:errcheck — -wx: write ok, list not
		}}, nil
	}
	if _, err := ensureIndex(env.arc); err == nil {
		t.Fatal("listSegments failure after write silently accepted")
	}
	os.Chmod(env.arc.dir, 0o700) //nolint:errcheck — restore before cleanup
	if segs, _ := listSegments(env.arc); len(segs) != 1 {
		t.Fatalf("segment lost by post-write list fault: %d", len(segs))
	}
}

// Compaction: the merged segment writes fine, but the subsequent inventory
// readdir fails (-wx) — compaction must surface that and keep every original.
func TestCompactionPostWriteListFault(t *testing.T) {
	needPosixPerms(t)
	quietLog()
	env := newTestEnv(t)
	var names []string
	for i := 0; i < 17; i++ { // one more than idxMaxSegments
		mail := []byte("Subject: m" + string(rune('a'+i)) + "\r\n\r\nbody" + string(rune('a'+i)) + "x")
		if _, err := env.arc.put("acc", mail); err != nil {
			t.Fatal(err)
		}
		names = append(names, blobName("acc", mail))
	}
	for _, n := range names {
		if _, err := writeSegment(env.arc, mkTestSegment(n)); err != nil {
			t.Fatal(err)
		}
	}
	if segs, _ := listSegments(env.arc); len(segs) != 17 {
		t.Fatalf("setup: %d segments, want 17", len(segs))
	}
	env.arc.newWriter = func(w io.Writer, r ...age.Recipient) (io.WriteCloser, error) {
		inner, err := age.Encrypt(w, r...)
		if err != nil {
			return nil, err
		}
		return &sideClose{WriteCloser: inner, side: func() {
			os.Chmod(env.arc.dir, 0o333) //nolint:errcheck
		}}, nil
	}
	if _, err := ensureIndex(env.arc); err == nil {
		t.Fatal("post-compaction readdir failure silently accepted")
	}
	os.Chmod(env.arc.dir, 0o700) //nolint:errcheck
	// the merged segment already persisted before the readdir fault — the
	// redundant duplicate is harmless (dedup by coverage), the originals
	// were only removed after the inventory re-read failed
	if segs, _ := listSegments(env.arc); len(segs) != 18 {
		t.Fatalf("compaction fault lost originals: %d segments, want 17+1", len(segs))
	}
}

// queryIndex on an unreadable archive dir must fail (callers fall back to the
// raw scan) — silent empty results would hide a broken index.
func TestQueryIndexUnreadableDir(t *testing.T) {
	needPosixPerms(t)
	quietLog()
	env := newTestEnv(t)
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(env.arc.dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(env.arc.dir, 0o700) })
	if _, err := queryIndex(env.arc, "alpha"); err == nil {
		t.Fatal("queryIndex ignored unreadable archive dir")
	}
}

// loadSegment recovery ladder: corrupt plaintext cache AND vanished encrypted
// source — the cache error must win, not a confusing miss.
func TestLoadSegmentCorruptCacheVanishedSource(t *testing.T) {
	quietLog()
	env := newTestEnv(t)
	if _, err := env.arc.put("acc", []byte("Subject: one\r\n\r\nalpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIndex(env.arc); err != nil {
		t.Fatal(err)
	}
	segs, _ := listSegments(env.arc)
	if len(segs) != 1 {
		t.Fatalf("setup: %d segments", len(segs))
	}
	// poison the plaintext cache, then delete the encrypted source
	cache := filepath.Join(userCfgDir(), "index-cache", strings.TrimSuffix(strings.TrimPrefix(segs[0], ".idx-"), ".age"))
	if err := os.WriteFile(cache, []byte("garbage-not-a-segment"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(env.arc.dir, segs[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSegment(env.arc, segs[0]); err == nil {
		t.Fatal("loadSegment accepted corrupt cache without source")
	}
}
