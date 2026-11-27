# cloud-email-archive

![how it works](assets/teaser.svg)

A single static Go binary (no runtime dependencies): fetches email via IMAP
(Dovecot, Exchange, … — as many accounts as you like), encrypts it client-side
with [age](https://age-encryption.org), and stores it as content-addressed
blobs in a folder that your cloud sync/mount pushes to the provider —
Nextcloud, Syncthing, Dropbox, OneDrive, Google Drive, Seafile, an SMB/NFS
share, an `rclone` mount, or a plain USB drive.

```
IMAP (account 1..n: dovecot, exchange, …)
   │  cloud-email-archive sync   ── plaintext only in RAM
   ▼
age-encrypted blobs
   ▼
~/Nextcloud/email-archive/     ── any sync client/mount uploads opaque .age files
```

**Threat model:** the provider sees only encrypted blobs with cryptographic
names. No content, no subject lines, no senders, no folder structure. Content
addressing (filename = SHA-256 of the plaintext) makes deduplication pay off:
identical mails (e.g. in several folders or accounts) are stored once, and a
re-run only fetches mails that don't exist yet — incremental, like a backup
tool. Data is protected two ways: age is authenticated, any
modification shows up in `verify` — and verify also checks the
content-addressing guarantee itself (filename must equal the SHA-256 of the
decrypted mail), catching renames, copy bugs, or provider-side mangling.

## Build

```sh
go build -o cloud-email-archive ./cmd/cea   # single binary, cross-compilable (linux/darwin/windows)
```

Prebuilt linux/darwin binaries (amd64/arm64) with SHA256SUMS are published on
GitHub Releases for every `v*` tag.

## Setup (once)

Passphrase-protected key (recommended: the disk never holds the secret key in
the clear — every run asks for it, or reads it via `passphrase_cmd` /
`CEA_PASSPHRASE`):

```
cloud-email-archive keygen -passphrase
```

```sh
cp config.example.toml ~/.config/cloud-email-archive/config.toml
# Fill in your accounts (as many as you like). Password alternatives:
#   password = "..."  or  password_cmd = "cat ~/.config/imap-passwords/faculty"

cloud-email-archive keygen    # creates ~/.config/cloud-email-archive/key.txt  (IMPORTANT: back it up!)
cloud-email-archive sync      # first run
cloud-email-archive list      # sanity check: headers of archived mails
```

Point `archive_dir` in the config at a folder inside your synced/mounted share
(`~/Nextcloud/…`, `~/Sync/…`, `/mnt/share/…`, whatever your provider gives you).
Paths can be overridden in the TOML or via `-config FILE`;
`CLOUD_EMAIL_ARCHIVE_CONFIG` sets the default config location.

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
cloud-email-archive keygen  [-output FILE]
cloud-email-archive version                         # print version
```

## Freeing server space

The archive never deletes — but the mail server can, once the archive
provably holds the mail. The typical yearly cleanup:

```sh
cloud-email-archive sync -before 2025-01-01     # 1. archive last year's mail (only that)
cloud-email-archive verify                      # 2. prove every blob decrypts
cloud-email-archive expire -before 2025-01-01   # 3. dry run: shows exactly what would go
cloud-email-archive expire -before 2025-01-01 -do   # 4. delete those on the server
```

`expire` deletes on the server, never in the archive. It only ever touches a
message when *all* of this holds:

- the message's INTERNALDATE is before the cutoff (server-side `SEARCH
  BEFORE` intersected with the folder's remembered archive state),
- the folder's UIDVALIDITY matches the last sync (a changed UIDVALIDITY
  skips the folder — stale UIDs could point at different messages),
- a blob holding the *exact* message content exists in the archive and
  decrypts to the same SHA-256. Anything unproven is skipped with a warning.

Without `-do` the command is a dry run. Without `-before` it refuses to run.
Deletion is UID-scoped (`UID STORE \Deleted` + `UID EXPUNGE`), so it touches
exactly the proven set and nothing else — note that `UID EXPUNGE` needs the
server's UIDPLUS capability (Dovecot, Courier, most others have it). A full
`sync` afterwards is a clean no-op: the remaining server mail is already in
the archive, and the archive keeps everything — including what was just
deleted server-side.

## Search speed

Search runs against an **encrypted trigram index** that lives next to the
blobs (`.idx-<sha256>.age`) and is maintained automatically by every `sync`
(run `index` to build it on demand). The index is derived data: rebuildable
from blobs alone, byte-deterministic (same blobs ⇒ identical segment ⇒
multi-machine dedup, no sync conflicts), and verified against the archive on
every query. Measured on this project's benchmark corpus (details and
reproduction steps in [`docs/benchmark.md`](docs/benchmark.md)):

| Archive size | First index build | Later `index` runs | Search (indexed)  | Raw scan (`-raw`) |
| ------------:| -----------------:| ------------------:| -----------------:| -----------------:|
| 500 MB       | 2.9 s             | **4 ms**           | **~15 ms**        | ~7 s              |
| 8 GB         | 40–80 s           | **20–30 ms**       | **0.16 s** + one decrypt per match | 36–100 s |
| 500 GB (extrapolated) | ~1 h, one-time | seconds      | sub-second lookup | hours             |

- Queries only touch the searched term's trigram postings — lookup time is
  essentially independent of archive size (a no-match search over 8 GB took
  0.16 s). Matches are then confirmed by decrypting just the candidate
  blobs (each match costs one blob decrypt, which you would pay anyway to
  read the mail).
- The index covers decoded `text/*` parts (base64/quoted-printable decoded,
  RFC-822 nesting included) plus all headers; binary attachment *contents*
  are not indexed — use `search -raw` (exact bytes, slow) for those, or for
  terms shorter than 3 characters, or for byte ranges after the final MIME
  boundary.
- If the index is missing or damaged, search transparently falls back to the
  raw scan; a broken index never fails a sync or a search, and `verify`
  ignores index files (the mail blobs remain the only source of truth).

## Operation / Automation

```sh
crontab -e
# e.g. daily at 03:00:
0 3 * * * $HOME/cloud-email-archive sync >> "$HOME/cea-sync.log" 2>&1
# monthly integrity check:
@monthly $HOME/cloud-email-archive verify >> "$HOME/cea-verify.log" 2>&1
```

A `sync` run logs a final summary line (`sync done` with new messages/bytes),
one error line per failing account/folder, and exits non-zero if any account
failed — alert on the exit code, not on log noise.

Only one state-mutating command (`sync`, `expire`, `index`) may run per
profile at a time; the others refuse with
`another cloud-email-archive instance is running` while one is active
(advisory lock on `<state-file>.lock`, auto-released on exit). `view` and
`verify` are read-only and lock-free.

## Principles

- **Append-only:** nothing is ever deleted. Even if a mail disappears from the
  server, it stays in the archive — as an archive should.
- **No `\Seen` flag:** FETCH runs with `BODY.PEEK`; your inbox on the server
  stays untouched.
- **Incremental & resumable:** UID/UIDVALIDITY progress in `state.json`; on
  UIDVALIDITY change the folder is cleanly re-fetched. Interrupted runs simply
  continue where they left off. The search index is maintained the same way:
  each sync appends one small derived segment, never re-scans.
- **Provider-agnostic:** the archive is just files in a folder. Any storage
  that can sync or mount a directory works — no provider API in the binary.
- **Account types optional:** `[[accounts]]` is a generic list. Dovecot and
  Exchange are just examples — any IMAP account works, in any combination.

## Privacy — what is encrypted, what is not

The hard guarantee: **mail content and the search index are age-encrypted before
they ever touch disk**, and the archive folder contains no folder structure, no
subjects, no senders. What a provider (or a stolen backup) can see:

| Location | Sees | Protected? |
|---|---|---|
| Archive dir: `*.age` blobs | mail content | ✅ age (X25519 + ChaCha20-Poly1305) |
| Archive dir: `.idx-*.age` | full-text index | ✅ age, filename is a hash |
| Archive dir: blob **filenames** | account name (prefix), SHA-256 = dedup fingerprint, mail count and sizes | ⚠️ metadata, by design (prefix enables account-scoped reads without decrypting) |
| `~/.config/.../state.json` | accounts, **folder hierarchy**, per-folder message counts, UID→blob mapping | ✅ age armor (same recipient as the archive); legacy plaintext files migrate to armor on the next save |
| `~/.config/.../config.toml` | IMAP host/user, optionally `password` (prefer `password_cmd`) | ⚠️ local only |

`state.json` used to be the known gap: folder names were already its keys before
the folder-tree feature, and the UID→blob attribution lives there too. It is now
age-armored to the same recipient as the archive and written atomically — the
disk never sees plaintext state JSON. Existing plaintext state files keep loading
(no key needed) and migrate to armor on the next save. Combined with a
passphrase-protected key file, the complete metadata picture is now encrypted at
rest: only while a command runs, with the passphrase supplied, does the folder
hierarchy exist outside the encrypted blobs.

**Transport security**: the default is IMAPS/implicit TLS (port 993) with
certificate verification against the system pool and a TLS-1.2 minimum —
`security = "starttls"` and the self-signed-CA escape hatch `SSL_CERT_FILE`
are supported. `security = "none"` (unencrypted IMAP) exists but is loudly
warned about at runtime. There is no `insecure_skip_verify` option — there
is nothing to disable. The encrypted path is proven end to end by
`TestSyncImplicitTLSEndToEnd` (handshake → login → fetch → state →
reconnect, against a verified certificate).

## Recovery

The key is `~/.config/cloud-email-archive/key.txt`. **Without this key the
archive is unreadable** — keep a copy in your password manager. To restore on
another machine: drop binary + `config.toml` + `key.txt`, run
`cloud-email-archive extract`/`list` against the synced archive folder.

## Details

- IMAP client: [`emersion/go-imap/v2`](https://github.com/emersion/go-imap) (pure Go)
- Encryption: [`filippo.io/age`](https://age-encryption.org/v1) (X25519/ChaCha20-Poly1305, audited)
- Config: TOML
- Further architecture decisions: see `docs/arc42/`

## Testing

The suite runs against an in-memory IMAP server (`go test ./...`), plus two
opt-in tiers:

```sh
# real-server tier: full sync→verify→expire flow against Dovecot in Docker
# (exercises foreign UIDPLUS / SEARCH BEFORE / INTERNALDATE implementations)
go test -tags integration -run TestDovecot -v

# true-binary E2E: builds the binary and drives it via exec
# (runs as part of the normal suite)
go test -run TestE2EBinary -v
```

CI additionally runs the suite on `windows-latest` (portable subset: the
single-writer flock is a Unix syscall; on Windows the lock stub is a no-op
and POSIX-permission fault-injection tests skip themselves) and a timezone
matrix, since all date logic is cutoff-based.

### Mutation campaign

The safety gates (UIDVALIDITY guard, INTERNALDATE drift guard, truncation
guards, proof equality, flock, dry-run default) are enforced by tests, not
just present: `scripts/mutate.sh` weakens each gate one at a time and requires
the targeted test to fail. A mutation that compiles and runs but whose test
still passes is reported as SURVIVED and fails the script — that is the
signal to strengthen the test. Statement coverage alone misses this class:
the proof-equality gate had 100% statement coverage while its false branch
was never asserted (found by exactly this campaign).

## License

Apache License 2.0, see [LICENSE](LICENSE). Copyright 2026 Tobias Weiß.
Contributions are welcome under the license's inbound=outbound rule
(no separate contributor agreement); security-relevant findings go to the
contact in [SECURITY.md](.github/SECURITY.md), not to public issues.
