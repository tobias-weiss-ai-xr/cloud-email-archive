package app

// Fuzzing for the untrusted-input surface: archived RFC822 bytes come from
// arbitrary mail servers, so parseHeaders must never panic and must never
// leak raw line breaks into extracted header values. Run the seed corpus with
// `go test` (automatic); to actually fuzz: go test -fuzz FuzzParseHeaders.

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func FuzzParseHeaders(f *testing.F) {
	f.Add([]byte("From: a@x\r\nSubject: plain\r\nDate: Mon, 02 Jan 2006 15:04:05 +0100\r\n\r\nbody\r\n"))
	f.Add([]byte("Subject: folded first\r\n continuation line\r\nFrom: x@y\r\n\r\nno date\r\n"))
	f.Add([]byte("Subject: lf-only\nFrom: x@y\n\nbody\n"))
	f.Add([]byte("no colon header\r\n\r\nbody"))
	f.Add([]byte("Subject: dup\r\nSubject: second wins-no\r\n\r\n\r\n"))
	f.Add([]byte("Date: garbage not a date\r\n\r\n"))
	f.Add([]byte(""))
	f.Add([]byte("\r\n\r\n\r\n"))
	f.Add([]byte("Subject: \xff\xfe invalid utf8\r\n\r\n"))
	f.Add([]byte("SuBjeCt:00\r0\n\n"))                     // regression: bare-CR normalization (fuzzer-found)
	f.Add([]byte("Subject: \x1b[31m red escape \r\n\r\n")) // regression: terminal escape stripping
	f.Add([]byte("Subject: tab\tcontinuation\r\n \t more\r\nFrom: a\r\n\r\n"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		date, from, subject := parseHeaders(raw)
		// never panics; date must be epoch (unparsable/missing) or a real date
		if date.Before(time.Unix(0, 0)) {
			t.Errorf("date before epoch: %v (input %q)", date, raw)
		}
		// header values are single unfolded, control-stripped lines
		for label, v := range map[string]string{"from": from, "subject": subject} {
			if strings.ContainsFunc(v, func(r rune) bool { return (r < 0x20 && r != '\t') || r == 0x7f }) {
				t.Errorf("%s contains control char: %q (input %q)", label, v, raw)
			}
		}
	})
}

// Index segments are content-addressed files in the (provider-visible) sync
// folder and plaintext cache entries — both can be corrupted or tampered
// with. unmarshalSegment must reject garbage instead of panicking. Seeds also
// pin the canonical format. To fuzz: go test -fuzz FuzzSegmentParse.
func FuzzSegmentParse(f *testing.F) {
	s := mkTestSegment("acc_aaa", "acc_bbb")
	f.Add(s.marshal())
	f.Add([]byte(idxMagic))
	f.Add([]byte(idxMagic + "short"))
	good := s.marshal()
	// corrupt the postings area: flip the last byte
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0xff
	f.Add(bad)
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := unmarshalSegment(data)
		if err != nil {
			return // rejection is fine; panic or hang is not
		}
		// any accepted segment must re-serialize to identical bytes
		if !bytes.Equal(s.marshal(), data) {
			t.Fatalf("accepted segment is not canonical: %x vs %x", s.marshal(), data)
		}
	})
}
