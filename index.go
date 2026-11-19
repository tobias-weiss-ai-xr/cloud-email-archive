package main

// Encrypted trigram search index over decoded mail text.
//
// The index is DERIVED data: it can always be rebuilt from the blobs alone and
// is never authoritative. Segments are canonical serializations (everything
// sorted, delta-varint postings), so the same input blobs always produce
// byte-identical output — segments are content-addressed like mail blobs
// (.idx-<sha256>.age) and therefore converge across machines and dedupe in
// Nextcloud instead of conflicting.
//
// What is indexed: the raw header block plus every decoded text/* MIME part
// (base64/quoted-printable decoded), lowercased. Binary attachments are not
// indexed; `search --raw` still scans raw bytes exhaustively.
//
// Scale notes (500 GB class): queries touch only the queried trigrams'
// postings; post-compaction steady state is a single segment whose coverage
// hash short-circuits the per-search coverage check. A plaintext local cache
// of decrypted segments lives under the user config dir (same trust domain
// as `extract` output; the provider never sees it). Index failures never
// fail a sync or a search — everything falls back to the raw scan.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"filippo.io/age"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	idxMagic       = "CEAIDX1"
	idxMaxSegments = 16  // compact when more than this many segments exist
	idxMaxNameLen  = 255 // blob names are file names; fs paths cap at 255 bytes
)

// ErrShortTerm signals a query too short for trigrams; caller falls back to
// the raw scan.
var ErrShortTerm = errors.New("term shorter than 3 bytes needs raw scan")

// idxSegment holds the postings for a set of blobs.
type idxSegment struct {
	covHash [32]byte             // sha256 over the covered blob names, concatenated
	blobs   []string             // sorted covered blob names
	tri     map[[3]byte][]uint32 // trigram -> sorted ascending blob indices
}

// coverageHash returns the hash identifying a set of blob names.
func coverageHash(names []string) [32]byte {
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// marshal emits the canonical segment bytes. Deterministic: identical inputs
// always produce identical bytes, so identical segments get identical names.
func (s *idxSegment) marshal() []byte {
	buf := bytes.NewBuffer(nil)
	buf.WriteString(idxMagic)
	buf.Write(s.covHash[:])
	putUvarint(buf, uint64(len(s.blobs)))
	for _, name := range s.blobs { // sorted
		putUvarint(buf, uint64(len(name)))
		buf.WriteString(name)
	}
	keys := make([][3]byte, 0, len(s.tri))
	for k := range s.tri {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	putUvarint(buf, uint64(len(keys)))
	for _, k := range keys {
		buf.Write(k[:])
		list := s.tri[k]
		putUvarint(buf, uint64(len(list)))
		prev := uint32(0)
		for i, v := range list {
			if i == 0 {
				putUvarint(buf, uint64(v))
			} else {
				putUvarint(buf, uint64(v-prev))
			}
			prev = v
		}
	}
	return buf.Bytes()
}

func putUvarint(buf *bytes.Buffer, v uint64) {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	buf.Write(tmp[:n])
}

func getUvarint(b *bytes.Reader) (uint64, error) {
	var v uint64
	var shift uint
	n := 0
	for {
		// defense-in-depth: unreachable today (a 10th continuation byte always
		// trips the overflow check below, since c >= 0x80 > 1 at shift >= 63),
		// but guards the loop if the shift logic is ever refactored
		if n == binary.MaxVarintLen64 {
			return 0, errors.New("varint too long")
		}
		c, err := b.ReadByte()
		if err != nil {
			return 0, err
		}
		n++
		if shift >= 63 && c > 1 {
			return 0, errors.New("varint overflow")
		}
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			// canonical gate: re-encoding must produce the same byte count
			// (rejects overlong encodings like 0x80 0x00 for zero)
			var tmp [binary.MaxVarintLen64]byte
			if binary.PutUvarint(tmp[:], v) != n {
				return 0, errors.New("non-canonical varint encoding")
			}
			return v, nil
		}
		shift += 7
	}
}

func unmarshalSegment(data []byte) (*idxSegment, error) {
	b := bytes.NewReader(data)
	magic := make([]byte, len(idxMagic))
	if _, err := io.ReadFull(b, magic); err != nil || string(magic) != idxMagic {
		return nil, errors.New("bad index segment magic")
	}
	s := &idxSegment{tri: map[[3]byte][]uint32{}}
	if _, err := io.ReadFull(b, s.covHash[:]); err != nil {
		return nil, fmt.Errorf("coverage hash: %w", err)
	}
	nBlobs, err := getUvarint(b)
	if err != nil {
		return nil, fmt.Errorf("blob count: %w", err)
	}
	for i := uint64(0); i < nBlobs; i++ {
		ln, err := getUvarint(b)
		if err != nil {
			return nil, fmt.Errorf("blob name len: %w", err)
		}
		if ln > idxMaxNameLen {
			return nil, fmt.Errorf("blob name too long: %d bytes", ln)
		}
		name := make([]byte, ln)
		if _, err := io.ReadFull(b, name); err != nil {
			return nil, fmt.Errorf("blob name: %w", err)
		}
		s.blobs = append(s.blobs, string(name))
	}
	nTri, err := getUvarint(b)
	if err != nil {
		return nil, fmt.Errorf("trigram count: %w", err)
	}
	var prevKey [3]byte
	for i := uint64(0); i < nTri; i++ {
		var key [3]byte
		if _, err := io.ReadFull(b, key[:]); err != nil {
			return nil, fmt.Errorf("trigram key: %w", err)
		}
		if i > 0 && bytes.Compare(key[:], prevKey[:]) <= 0 {
			return nil, errors.New("trigram keys not strictly ascending")
		}
		prevKey = key
		n, err := getUvarint(b)
		if err != nil {
			return nil, fmt.Errorf("posting len: %w", err)
		}
		if n > uint64(len(s.blobs)) {
			return nil, fmt.Errorf("posting list %d exceeds blob count %d", n, len(s.blobs))
		}
		list := make([]uint32, n)
		var acc uint64
		for j := range list {
			d, err := getUvarint(b)
			if err != nil {
				return nil, fmt.Errorf("posting delta: %w", err)
			}
			acc += d
			if acc >= uint64(len(s.blobs)) {
				return nil, fmt.Errorf("posting index %d out of range (%d blobs)", acc, len(s.blobs))
			}
			list[j] = uint32(acc)
			if j > 0 && list[j] <= list[j-1] {
				return nil, errors.New("postings not strictly ascending")
			}
		}
		s.tri[key] = list
	}
	// verify consistency: coverage hash matches blob list, and no trailing
	// bytes may hide after the last posting (segments are canonical)
	if b.Len() != 0 {
		return nil, fmt.Errorf("%d trailing bytes after segment body", b.Len())
	}
	if got := coverageHash(s.blobs); got != s.covHash {
		return nil, errors.New("coverage hash mismatch")
	}
	return s, nil
}

// segmentName is the content-addressed file name for segment bytes.
func segmentName(data []byte) string {
	sum := sha256.Sum256(data)
	return ".idx-" + hex.EncodeToString(sum[:]) + ".age"
}

// writeSegment encrypts canonical segment bytes and stores them under their
// content hash. Returns the file name.
func writeSegment(a *Archive, s *idxSegment) (string, error) {
	data := s.marshal()
	name := segmentName(data)
	tmp, err := os.CreateTemp(a.dir, ".idx-*.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	w, err := a.newWriter(tmp, a.id.Recipient())
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if err := w.Close(); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(tmpPath, filepath.Join(a.dir, name)); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	return name, nil
}

// loadSegment reads a segment by file name, using the local plaintext cache
// when possible (re-encrypting the same bytes would defeat the point).
func loadSegment(a *Archive, name string) (*idxSegment, error) {
	hash := strings.TrimSuffix(strings.TrimPrefix(name, ".idx-"), ".age")
	cache := filepath.Join(userCfgDir(), "index-cache", hash)
	var data []byte
	if b, err := os.ReadFile(cache); err == nil {
		data = b
	} else {
		b, err := a.get(name)
		if err != nil {
			return nil, err
		}
		data = b
		// best-effort cache write (plaintext index stays on this machine)
		if err := os.MkdirAll(filepath.Dir(cache), 0o700); err == nil {
			tmp := cache + ".tmp"
			if err := os.WriteFile(tmp, data, 0o600); err == nil {
				os.Rename(tmp, cache) //nolint:errcheck
			}
		}
	}
	s, err := unmarshalSegment(data)
	if err != nil {
		// corrupted cache entry: drop it and retry from the encrypted source
		os.Remove(cache) //nolint:errcheck
		b, err2 := a.get(name)
		if err2 != nil {
			return nil, err
		}
		s, err = unmarshalSegment(b)
		if err != nil {
			return nil, err
		}
		// re-populate the cache with the verified plaintext
		if err := os.MkdirAll(filepath.Dir(cache), 0o700); err == nil {
			tmp := cache + ".tmp"
			if werr := os.WriteFile(tmp, b, 0o600); werr == nil {
				os.Rename(tmp, cache) //nolint:errcheck
			}
		}
		return s, nil
	}
	return s, nil
}

// listSegments returns the index segment file names present in the archive.
func listSegments(a *Archive) ([]string, error) {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // fresh install: archive dir is created on first sync
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".idx-") && strings.HasSuffix(e.Name(), ".age") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// segmentCoverageHash peeks only the header (magic + coverage hash). Age's
// STREAM construction decrypts chunk-wise, so a limited read touches only the
// first chunk — no full-segment decrypt for the steady-state fast path.
func segmentCoverageHash(a *Archive, name string) ([32]byte, error) {
	var out [32]byte
	f, err := os.Open(filepath.Join(a.dir, name))
	if err != nil {
		return out, err
	}
	defer f.Close()
	// no size limit here: age.Decrypt reads only the (few-hundred-byte)
	// header, and the plaintext ReadFull below pulls exactly one STREAM chunk
	// (~64 KiB) — far less than decrypting the whole segment
	r, err := age.Decrypt(f, a.id)
	if err != nil {
		return out, err
	}
	hdr := make([]byte, len(idxMagic)+32)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return out, err
	}
	if string(hdr[:len(idxMagic)]) != idxMagic {
		return out, errors.New("bad index segment magic")
	}
	copy(out[:], hdr[len(idxMagic):])
	return out, nil
}

// buildSegment indexes the given blob names (sorted internally, so callers
// cannot produce order-dependent segments).
func buildSegment(a *Archive, names []string) (*idxSegment, error) {
	names = append([]string(nil), names...)
	sort.Strings(names)
	s := &idxSegment{
		covHash: coverageHash(names),
		blobs:   names,
		tri:     map[[3]byte][]uint32{},
	}
	for i, name := range names {
		raw, err := a.get(name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		text := searchableText(raw)
		// dedupe trigrams per blob first: repeated words would otherwise hit
		// the global map once per occurrence, and only unique (trigram, blob)
		// pairs belong in the postings anyway
		seen := make(map[[3]byte]struct{}, len(text)/8+16)
		for j := 0; j+3 <= len(text); j++ {
			var key [3]byte
			copy(key[:], text[j:j+3])
			seen[key] = struct{}{}
		}
		// blobs are processed in ascending index order, so every postings list
		// is built ascending by construction — no global sort needed
		for key := range seen {
			s.tri[key] = append(s.tri[key], uint32(i))
		}
	}
	return s, nil
}

// dedupSorted removes duplicates from an ascending slice in place.
func dedupSorted(list []uint32) []uint32 {
	out := list[:0]
	for i, v := range list {
		if i == 0 || v != list[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// ensureIndex brings the index up to date: indexes blobs not yet covered and
// compacts when too many segments have accumulated. Returns segment count.
func ensureIndex(a *Archive) (int, error) {
	blobs, err := a.blobs()
	if err != nil {
		return 0, err
	}
	names := make([]string, len(blobs))
	for i, b := range blobs {
		names[i] = b.name
	}
	full := coverageHash(names)

	segNames, err := listSegments(a)
	if err != nil {
		// honest gap: unreachable — blobs() listed this same dir with the
		// same permissions moments ago; a directory cannot pass ReadDir and
		// then fail it before any syscall in between
		return 0, err
	}
	// fast path: a segment already covers exactly this blob set
	for _, sn := range segNames {
		if h, err := segmentCoverageHash(a, sn); err == nil && h == full {
			return len(segNames), nil
		}
	}

	covered := map[string]bool{}
	healthy := 0 // segment files that parsed fine
	for _, sn := range segNames {
		s, err := loadSegment(a, sn)
		if err != nil {
			// segments are derived data: a corrupt one is deleted, its blobs
			// count as uncovered and get re-indexed (self-healing)
			os.Remove(filepath.Join(a.dir, sn)) //nolint:errcheck
			continue
		}
		healthy++
		for _, b := range s.blobs {
			covered[b] = true
		}
	}
	segNames = segNames[:healthy]
	var missing []string
	for _, n := range names {
		if !covered[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		seg, err := buildSegment(a, missing)
		if err != nil {
			return 0, err
		}
		if _, err := writeSegment(a, seg); err != nil {
			return 0, err
		}
		segNames, err = listSegments(a)
		if err != nil {
			return 0, err
		}
	}
	if len(segNames) > idxMaxSegments {
		if err := compactIndex(a, segNames); err != nil {
			return len(segNames), err
		}
		segNames = segNames[:1]
	}
	// drop cache entries whose segment is gone (self-heal deletions, manual
	// cleanup) — cheap read-dir compared to everything above
	pruneIndexCache(a)
	return len(segNames), nil
}

// compactIndex merges all segments into one and removes the old files.
func compactIndex(a *Archive, segNames []string) error {
	merged := &idxSegment{tri: map[[3]byte][]uint32{}}
	blobSet := map[string]int{}
	for _, sn := range segNames {
		s, err := loadSegment(a, sn)
		if err != nil {
			return err
		}
		for _, b := range s.blobs {
			if _, ok := blobSet[b]; !ok {
				blobSet[b] = len(merged.blobs)
				merged.blobs = append(merged.blobs, b)
			}
		}
		remap := make([]uint32, len(s.blobs))
		for i, b := range s.blobs {
			remap[i] = uint32(blobSet[b])
		}
		for k, list := range s.tri {
			dst := merged.tri[k]
			for _, v := range list {
				dst = append(dst, remap[v])
			}
			merged.tri[k] = dst
		}
	}
	sort.Strings(merged.blobs)
	// blobSet indices were assigned pre-sort; rebuild mapping after sort
	oldOrder := make([]string, len(merged.blobs))
	copy(oldOrder, merged.blobs)
	sort.Strings(merged.blobs)
	newIdx := make(map[string]uint32, len(merged.blobs))
	for i, b := range merged.blobs {
		newIdx[b] = uint32(i)
	}
	for k, list := range merged.tri {
		for i, v := range list {
			list[i] = newIdx[oldOrder[v]]
		}
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
		list = dedupSorted(list)
		if len(list) == 0 {
			delete(merged.tri, k)
		} else {
			merged.tri[k] = list
		}
	}
	merged.covHash = coverageHash(merged.blobs)

	name, err := writeSegment(a, merged)
	if err != nil {
		return err
	}
	keep := map[string]bool{name: true}
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, ".idx-") && strings.HasSuffix(n, ".age") && !keep[n] {
			os.Remove(filepath.Join(a.dir, n)) //nolint:errcheck
		}
	}
	pruneIndexCache(a)
	return nil
}

// pruneIndexCache drops cached segment data that no longer has a segment file.
func pruneIndexCache(a *Archive) {
	segNames, err := listSegments(a)
	if err != nil {
		// honest gap: unreachable — prune runs at the end of a successful
		// ensureIndex/compactIndex, which just listed this same directory
		return
	}
	live := map[string]bool{}
	for _, n := range segNames {
		live[strings.TrimSuffix(strings.TrimPrefix(n, ".idx-"), ".age")] = true
	}
	cacheDir := filepath.Join(userCfgDir(), "index-cache")
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !live[e.Name()] {
			os.Remove(filepath.Join(cacheDir, e.Name())) //nolint:errcheck
		}
	}
}

// queryIndex returns the blob names whose decoded text may contain term.
// Trigram containment is necessary but not sufficient (trigrams can be
// scattered), so callers must verify by decrypting candidates.
func queryIndex(a *Archive, term string) ([]string, error) {
	if len(term) < 3 {
		return nil, ErrShortTerm
	}
	segNames, err := listSegments(a)
	if err != nil {
		return nil, err
	}
	if len(segNames) == 0 {
		return nil, errors.New("no index segments present")
	}
	var keys [][3]byte
	for j := 0; j+3 <= len(term); j++ {
		var key [3]byte
		copy(key[:], term[j:j+3])
		keys = append(keys, key)
	}
	cand := map[string]bool{}
	for _, sn := range segNames {
		s, err := loadSegment(a, sn)
		if err != nil {
			return nil, err
		}
		var inter []uint32
		for i, k := range keys {
			list, ok := s.tri[k]
			if !ok || len(list) == 0 {
				inter = nil
				break
			}
			if i == 0 {
				inter = list
				continue
			}
			inter = intersectSorted(inter, list)
			if len(inter) == 0 {
				break
			}
		}
		for _, v := range inter {
			if v < uint32(len(s.blobs)) {
				cand[s.blobs[v]] = true
			}
		}
	}
	out := make([]string, 0, len(cand))
	for c := range cand {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

func intersectSorted(a, b []uint32) []uint32 {
	// allocate: callers pass slices owned by loaded segments; never mutate them
	out := make([]uint32, 0, min(len(a), len(b)))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			i++
		case a[i] > b[j]:
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	return out
}

// searchIndexed runs the fast path: ensure fresh coverage, query candidates,
// verify each by decrypting + extracting text. Falls back with an error when
// the index is stale (caller decides whether to raw-scan).
func searchIndexed(env *cmdEnv, term string) (int, error) {
	if _, err := ensureIndex(env.arc); err != nil {
		return 0, fmt.Errorf("index update: %w", err)
	}
	cands, err := queryIndex(env.arc, term)
	if err != nil {
		return 0, err
	}
	matches := 0
	for _, name := range cands {
		account := accountOf(name)
		if env.account != "" && !strings.EqualFold(account, env.account) {
			continue
		}
		raw, err := env.arc.get(name)
		if err != nil {
			continue // blob vanished since indexing; not a search failure
		}
		if !strings.Contains(string(searchableText(raw)), term) {
			continue // trigram false positive
		}
		printMsg(account, raw)
		matches++
	}
	return matches, nil
}

// searchableText extracts everything the index (and indexed search) considers
// text: the raw header block plus decoded text/* MIME parts, lowercased,
// CR-stripped. Parse failures degrade to raw bytes (never fail).
func searchableText(raw []byte) []byte {
	var buf bytes.Buffer
	appendMailText(&buf, raw)
	out := bytes.ToLower(buf.Bytes())
	return bytes.ReplaceAll(out, []byte("\r"), nil)
}

func appendMailText(buf *bytes.Buffer, raw []byte) {
	split := bytes.Index(raw, []byte("\r\n\r\n"))
	nl := 4
	if split < 0 {
		split = bytes.Index(raw, []byte("\n\n"))
		nl = 2
	}
	if split < 0 {
		buf.Write(raw) // no header/body split: treat everything as text
		return
	}
	buf.Write(raw[:split+nl]) // header block (folded headers stay intact)
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		buf.Write(raw[split+nl:]) // unparseable body: degrade to raw
		return
	}
	appendEntity(buf, msg.Header.Get("Content-Type"), msg.Header.Get("Content-Transfer-Encoding"), msg.Body)
}

func appendEntity(buf *bytes.Buffer, contentType, cte string, body io.Reader) {
	mediatype, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediatype = "text/plain"
	}
	switch {
	case strings.HasPrefix(mediatype, "multipart/"):
		if params["boundary"] == "" {
			return
		}
		mr := multipart.NewReader(body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			appendEntity(buf, part.Header.Get("Content-Type"), part.Header.Get("Content-Transfer-Encoding"), part)
		}
	case mediatype == "message/rfc822":
		sub, err := io.ReadAll(transferDecoder(cte, body))
		if err == nil {
			appendMailText(buf, sub)
		}
	case strings.HasPrefix(mediatype, "text/"):
		b, err := io.ReadAll(transferDecoder(cte, body))
		if err == nil {
			buf.Write(b)
			buf.WriteByte('\n')
		}
	}
}

func transferDecoder(cte string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}
