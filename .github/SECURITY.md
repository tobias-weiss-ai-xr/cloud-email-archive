# Security policy

This tool holds people's mail archives. If you find a way to read archive
content, weaken the encryption, or bypass the dry-run/never-delete defaults,
please report it privately.

## Reporting

Email **weissto@staff.uni-marburg.de** (private mail). Please do not open a
public issue for exploitable findings. Include the version
(`cloud-email-archive --version`), platform, and a minimal reproduction or
description. I aim to respond within a week.

## Supported versions

| version | supported |
|---|---|
| latest tagged release | yes |
| main | best effort |

## Scope

In scope: the age envelope (blob + index + state encryption), key file
handling (plaintext and passphrase-protected), passphrase resolution chain
(`CEA_PASSPHRASE`, `passphrase_cmd`, terminal prompt), the TLS posture
(implicit TLS default, STARTTLS, certificate verification), and the
delete-path guarantees (dry-run default, proof-before-expunge, flock).

Out of scope: brute-force attacks on scrypt/X25519 themselves, compromised
endpoint while a command is running with the key in memory (documented
boundary in docs/arc42/README.md §8.1).

## Hardening notes for operators

- Prefer `keygen -passphrase` and supply the passphrase via `passphrase_cmd`
  or `CEA_PASSPHRASE` from a 0600 file, never inline.
- Keep `state_file` outside the synced archive directory (default does this).
- Do not lower `security` below the implicit-TLS default; `security = "none"`
  exists only for firewalled test rigs.
