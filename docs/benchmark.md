# Benchmarks

All numbers measured on the development machine (Intel Core Ultra 5 125U,
NVMe SSD, Linux) with release builds of this binary and real `age` (X25519 +
ChaCha20-Poly1305) encryption. Decryption throughput is the common
bottleneck: every read path (`list`, `search`, `extract`, `verify`) decrypts
everything it touches, so wall-clock scales with archive size at roughly the
verify rate.

Reproduce the scale numbers yourself:

```sh
# corpus generation + archive build (opt-in, deterministic corpus)
CEA_SCALE_MB=500  go test -run TestScaleCorpus -timeout 30m .
CEA_SCALE_MB=8192 go test -run TestScaleCorpus -timeout 60m .
# then drive the real binary against /tmp/cea-scale/config.toml
go build -o /tmp/cea-scale/cea ../cmd/cea && cd /tmp/cea-scale
time ./cea index  -config config.toml
time ./cea search -config config.toml zebratail
time ./cea search -config config.toml -raw zebratail
time ./cea verify -config config.toml

# in-process regression benchmarks (32 MB by default)
go test -run XXX -bench BenchmarkIndex -benchtime 3x .
CEA_BENCH_MB=500 go test -run XXX -bench BenchmarkIndexBuild -benchtime 1x .
```

## Real-conditions stress test (533 MB, commit a0d4a7b)

Corpus: 113 unique mails + 1 duplicate (533.5 MB: PDFs 1–3 MB, images, zips
8–60 MB, calendar ICS, CRLF line endings), seeded to a **real Dovecot 2.4**
server, archive in a **real `~/Nextcloud`** folder, connected through a
kubectl port-forward (≈0.9 MB/s — the tunnel, not the tool, was the limit).

| Operation                  | Result                                  |
| -------------------------- | --------------------------------------- |
| Full sync (114 mails in)   | 676 s — tunnel-bound at 0.9 MB/s        |
| Incremental (no-op) sync   | 0.5 s                                   |
| Peak RAM during sync       | 194 MB (streaming, corpus-independent)  |
| `verify` (533 MB)          | 1.99 s (256 MB/s decrypt + SHA-256)     |
| `extract` all 113 mails    | 1.33 s (400 MB/s), all byte-identical   |
| Disaster restore (blobs + key only, no state/server) | 1.32 s, 113/113 byte-identical |
| Dedup                      | 114 mails in → 113 blobs                |

## Search: raw scan vs trigram index

Synthetic corpus (deterministic, realistic mix: ~55 % text/html mails,
20 % with 1–3 MB PDF attachments, 10 % images, 10 % calendar/zip, base64
encoded attachments like real mail):

| Archive | Mails | `index` cold build | `index` warm (peek) | Segment size | Search (indexed) | Search (`--raw`) | `verify` |
| -------:| ----:| ------------------:| -------------------:| ------------:| ----------------:| ----------------:| --------:|
| 500 MB  | 180  | 2.9 s (≈180 MB/s)  | **4 ms**            | 0.6 MB       | **15 ms**        | 6.7 s            | 5.3 s    |
| 8.2 GB  | 3060 | 40–80 s (disk-bound)| **20–30 ms**       | 9.1 MB       | **0.67 s**¹      | 36 s²            | 98 s     |

¹ 62 matching mails found and verified (each match costs one blob decrypt
≈ 2.7 MB here). A term matching nothing completes in **0.16 s** — pure
trigram lookup, independent of archive size.
² OS page cache warm after `verify`; ~100 s from a cold cache.

How to read this:

- **Index build is decrypt-bound**: it costs about one `verify` pass the
  first time. `sync` maintains the index incrementally, so after the first
  build you never pay it again — a `search` right after a normal sync finds
  the index already current.
- **The steady-state check is a header peek**: re-running `index` (or the
  index maintenance inside `search`/`sync`) verifies each segment's coverage
  hash from the first age STREAM chunk (~64 KiB) — 4 ms at 500 MB,
  20–30 ms at 8 GB, independent of archive size.
- **Indexed queries touch only the query's trigram postings** — 8 GB or
  500 GB makes almost no difference for the lookup itself.
- **Verification of candidates is the real cost**: the trigram index is a
  *necessary condition* index (trigrams can be scattered), so matches are
  confirmed by decrypting each candidate blob. A term that matches 20 mails
  of 2 MB each costs ~0.2 s on top of the lookup — and you would decrypt
  those mails anyway to read them.
- **Segment size is ~0.1 % of the archive** for attachment-heavy corpora
  (only decoded `text/*` parts are indexed). Text-only archives index
  roughly 10–40 % of their size. Segments live in the archive folder as
  `.idx-<sha256>.age` and sync/dedup like any blob.
- **Plaintext cache**: to avoid re-decrypting the segment on every query,
  the decrypted segment is cached under the user config dir (same machine,
  same trust domain as `extract` output). 9 MB at an 8 GB archive.

### Extrapolation to 500 GB

At the measured rates (106–205 MB/s disk-bound), a first full index build
over 500 GB would take 40–80 min — a one-time background cost, and `sync`
never rebuilds, it appends one small segment per run and compacts
occasionally (each later `index` run is a header peek, seconds at most).
After that, indexed search stays in the sub-second range for the lookup at
any archive size; raw scans would take about an hour per query and are only
needed for exact-byte searches (`--raw`) or terms shorter than 3 bytes.

## Index invariants (tested)

- Same blobs ⇒ byte-identical segment ⇒ identical content-addressed name:
  machines converging on the same archive produce the same segments and
  dedupe in the cloud folder (tested in `TestSegmentDeterministic`).
- Segments are derived data: a corrupt segment is detected, deleted, and
  rebuilt from blobs alone (`TestIndexSelfHeal`); index failure never fails
  a sync or a search (`TestCmdSearchIndexedFallsBackWhenIndexFails`).
- The segment parser rejects trailing bytes, non-canonical varints,
  duplicate keys, and oversized allocations — properties held against a
  3-minute `go test -fuzz FuzzSegmentParse` campaign (which found and
  fixed all of the above).
