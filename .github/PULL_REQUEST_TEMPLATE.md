## What

<!-- one or two sentences; what bug or feature -->

## Gates

- [ ] `go test ./...` green
- [ ] `go test -race ./...` green (required when sync/expire/lock changed)
- [ ] `TZ=Pacific/Kiritimati go test ./...` green (required when dates are involved)
- [ ] `scripts/mutate.sh` all mutations killed (required when a safety gate changed; clean tree needed)
- [ ] Encryption posture intact: no plaintext fallbacks, no skip-verify options, no secrets on the command line

## Notes for reviewers

<!-- anything surprising: state schema changes, error-class changes, new config fields -->
