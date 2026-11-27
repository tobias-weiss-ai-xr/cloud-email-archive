# Contributing

Thanks for looking at cloud-email-archive. Bug reports and pull requests are
welcome under the Apache-2.0 inbound=outbound rule — your PR is licensed under
Apache-2.0 automatically, no contributor agreement to sign.

## Bug reports

Open a GitHub issue. Include: `cloud-email-archive --version`, the command you
ran, and the exact output. For sync problems: the IMAP provider and its
`security` setting. Redact account names and folder names if they are
sensitive — the folder hierarchy is part of what this tool tries to keep off
other people's disks.

## Pull requests

1. `go test ./...` must pass.
2. Run the full gate battery if you touch sync/expire/lock logic:
   `go test -race ./...`, `TZ=Pacific/Kiritimati go test ./...`, and
   `scripts/mutate.sh` (needs a clean tree; it refuses dirty targets).
   The mutation campaign exists because a gate that passes on mutated code is
   worse than no gate.
3. Keep error messages actionable: say what failed, where, and what to try.
4. Never weaken the encryption posture: no plaintext fallbacks, no
   `InsecureSkipVerify`-style options, no passphrase-on-the-command-line.
   These are design decisions, not accidents (see docs/arc42/README.md, §8.1
   and ADRs 7–9).
5. New config fields follow the existing patterns (e.g. `*_cmd` indirection
   instead of inline secrets).

## Layout

- `cmd/cea/` — thin binary entry point
- `internal/app/` — everything else; state.go documents the bookkeeping
  schema, docs/arc42/README.md carries the architecture rationale
- `scripts/mutate.sh` — mutation campaign, see README "Mutation campaign"

## Security issues

Please report via the contact in SECURITY.md, not as a public issue.
