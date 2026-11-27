# cloud-email-archive

![how it works](assets/teaser.svg)

A single static Go binary (no runtime dependencies): fetches email via IMAP
(any number of accounts — Dovecot, Exchange, …), encrypts it client-side with
[age](https://age-encryption.org), and stores it as content-addressed blobs in
a folder that your cloud sync or mount pushes to the provider — Nextcloud,
Syncthing, Dropbox, OneDrive, Google Drive, Seafile, an SMB/NFS share, an
`rclone` mount, or a plain USB drive.

```
IMAP (account 1..n: dovecot, exchange, …)
   │  cloud-email-archive sync   ── plaintext only in RAM
   ▼
age-encrypted blobs
   ▼
~/Nextcloud/email-archive/     ── any sync client/mount uploads opaque .age files
```

**Threat model:** the provider sees only encrypted blobs with cryptographic
names — no content, no subjects, no senders, no folder structure. Content
addressing (filename = SHA-256 of the plaintext) makes deduplication pay off:
identical mails are stored once, and a re-run only fetches what the archive
lacks. `verify` decrypts and hash-checks every blob, so any modification or
provider-side mangling is detected.

## Install

Prebuilt binaries (linux/darwin/windows, amd64/arm64) with SHA256SUMS are on
[GitHub Releases](https://github.com/tobias-weiss-ai-xr/cloud-email-archive/releases),
or build it:

```sh
go build -o cloud-email-archive ./cmd/cea
```

## Setup (once)

```sh
cloud-email-archive keygen -passphrase    # recommended, see Privacy below
cp config.example.toml ~/.config/cloud-email-archive/config.toml
# edit: IMAP accounts (password = "..." or password_cmd = "..."), archive_dir
# (point it inside your synced/mounted share), folders to include

cloud-email-archive sync      # first run
cloud-email-archive list      # sanity check: headers of archived mails
```

With `-passphrase` every run reads the passphrase from `CEA_PASSPHRASE`,
`passphrase_cmd`, or a terminal prompt. Paths can be overridden via
`-config FILE`; `CLOUD_EMAIL_ARCHIVE_CONFIG` sets the default config location.

## Usage

```sh
cloud-email-archive sync    [-account NAME] [-before YYYY-MM-DD]  # fetch IMAP + encrypt (incremental)
cloud-email-archive list    [-account NAME] [-limit 20]
cloud-email-archive search  [-account NAME] TERM    # full-text search over decoded mail text
cloud-email-archive search  [-account NAME] -raw TERM  # exact-byte scan over raw mail bytes
cloud-email-archive index                           # build/update the search index (sync does this too)
cloud-email-archive extract [-dir OUT] [-dedup] [-account NAME]  # write decrypted .eml files
                                                              # (rebuilds the IMAP folder tree:
                                                              #  OUT/<account>/<folder>/<hash>.eml)
cloud-email-archive expire  [-account NAME] -before YYYY-MM-DD [-do]  # free server space
cloud-email-archive verify  [-account NAME]         # decrypt + hash-check every blob
cloud-email-archive keygen  [-output FILE] [-passphrase]
cloud-email-archive version
```

## Freeing server space

The archive never deletes — but the mail server can, once the archive provably
holds the mail. The typical yearly cleanup:

```sh
cloud-email-archive sync -before 2025-01-01     # 1. archive last year's mail (only that)
cloud-email-archive verify                      # 2. prove every blob decrypts
cloud-email-archive expire -before 2025-01-01   # 3. dry run: shows exactly what would go
cloud-email-archive expire -before 2025-01-01 -do   # 4. delete those on the server
```

`expire` deletes on the server, never in the archive, and only touches a
message when all of this holds:

- INTERNALDATE is before the cutoff (server-side `SEARCH BEFORE` intersected
  with the folder's remembered archive state),
- the folder's UIDVALIDITY matches the last sync (a changed UIDVALIDITY skips
  the folder — stale UIDs could point at different messages),
- a blob holding the exact message content exists and decrypts to the same
  SHA-256. Anything unproven is skipped with a warning.

Without `-do` it is a dry run; without `-before` it refuses to run. Deletion
is UID-scoped (`UID STORE \Deleted` + `UID EXPUNGE`), which needs the server's
UIDPLUS capability (Dovecot, Courier and most others have it). A full `sync`
afterwards is a clean no-op.

## Search

Search runs against an encrypted trigram index next to the blobs, maintained
automatically by every `sync`. The index is derived data: rebuildable from
blobs alone, byte-deterministic (no sync conflicts between machines), and
verified against the archive on every query. Numbers from
[`docs/benchmark.md`](docs/benchmark.md):

| Archive size | First index build | Later `index` runs | Search (indexed) | Raw scan (`-raw`) |
| ------------:| -----------------:| ------------------:| ----------------:| -----------------:|
| 500 MB       | 2.9 s             | **4 ms**           | **~15 ms**       | ~7 s              |
| 8 GB         | 40–80 s           | **20–30 ms**       | **0.16 s** + one decrypt per match | 36–100 s |
| 500 GB (extrapolated) | ~1 h, one-time | seconds      | sub-second       | hours             |

- The index covers decoded `text/*` parts plus all headers. Binary attachment
  contents, terms shorter than 3 characters, and ranges after the final MIME
  boundary need `search -raw`.
- A missing or damaged index never fails a search — it falls back to the raw
  scan. `verify` ignores index files; the mail blobs are the only source of
  truth.

## Automation

```sh
# daily sync at 03:00, monthly integrity check:
0 3 * * * $HOME/cloud-email-archive sync >> "$HOME/cea-sync.log" 2>&1
@monthly $HOME/cloud-email-archive verify >> "$HOME/cea-verify.log" 2>&1
```

A `sync` run exits non-zero if any account failed — alert on the exit code,
not on log noise. Only one state-mutating command (`sync`, `expire`, `index`)
runs per profile at a time (advisory lock on `<state-file>.lock`, auto-released
on exit); `list`, `search`, `extract` and `verify` are read-only and lock-free.

## Principles

- **Append-only:** nothing is ever deleted from the archive, even if a mail
  disappears from the server.
- **No `\Seen` flag:** fetches run with `BODY.PEEK`; your inbox on the server
  stays untouched.
- **Incremental & resumable:** progress lives in `state.json`; interrupted
  runs continue where they left off, and a UIDVALIDITY change re-fetches the
  folder cleanly.
- **Provider-agnostic:** the archive is just files in a folder — no provider
  API in the binary.
- **Any IMAP account works:** `[[accounts]]` is a generic list; Dovecot and
  Exchange are just examples, in any combination.

## Privacy — what is encrypted, what is not

Mail content, the search index, and the bookkeeping file (`state.json`:
accounts, folder hierarchy, message counts, UID→blob mapping) are age-encrypted
before they ever touch disk, written atomically. Plaintext state files from
older versions migrate to armor on the next save. With a passphrase-protected
key file the disk holds no secret key material in the clear — without the
passphrase, neither content nor metadata is readable.

| Location | Sees | Protected? |
|---|---|---|
| Archive dir: `*.age` blobs | mail content | ✅ age (X25519 + ChaCha20-Poly1305) |
| Archive dir: `.idx-*.age` | full-text index | ✅ age, filename is a hash |
| Archive dir: blob **filenames** | account name (prefix), SHA-256 = dedup fingerprint, mail count and sizes | ⚠️ metadata, by design |
| `~/.config/.../state.json` | accounts, **folder hierarchy**, per-folder message counts, UID→blob mapping | ✅ age armor (same recipient as the archive) |
| `~/.config/.../config.toml` | IMAP host/user, optionally `password` (prefer `password_cmd`) | ⚠️ local only |

Transport: IMAPS/implicit TLS (port 993) with certificate verification against
the system pool and a TLS-1.2 minimum is the default. `security = "starttls"`
and the self-signed-CA escape hatch `SSL_CERT_FILE` are supported;
`security = "none"` exists but warns loudly at runtime. There is no
`insecure_skip_verify` option.

## Recovery

The key is `~/.config/cloud-email-archive/key.txt`. **Without this key the
archive is unreadable** — keep a copy in your password manager. To restore on
another machine: drop binary + `config.toml` + `key.txt`, run
`cloud-email-archive extract`/`list` against the synced archive folder.

## Details

- IMAP client: [`emersion/go-imap/v2`](https://github.com/emersion/go-imap) (pure Go)
- Encryption: [`filippo.io/age`](https://age-encryption.org/v1) (X25519/ChaCha20-Poly1305, audited)
- Config: TOML
- Architecture decisions: [`docs/arc42/`](docs/arc42/README.md)
- Benchmark method & reproduction: [`docs/benchmark.md`](docs/benchmark.md)

## Testing

`go test ./...` runs the suite against an in-memory IMAP server plus a
true-binary E2E via exec. An opt-in tier drives a real sync→verify→expire flow
against Dovecot in Docker (foreign UIDPLUS/SEARCH BEFORE/INTERNALDATE
implementations):

```sh
go test -tags integration -run TestDovecot -v
```

CI additionally runs Windows and a timezone matrix (all date logic is
cutoff-based). The safety gates are test-enforced: `scripts/mutate.sh`
weakens each gate one at a time and requires the targeted test to fail.

## License

Apache License 2.0, see [LICENSE](LICENSE). Copyright 2026 Tobias Weiß.
Contributions are welcome under the license's inbound=outbound rule
(no separate contributor agreement); security-relevant findings go to the
contact in [SECURITY.md](.github/SECURITY.md), not to public issues.
