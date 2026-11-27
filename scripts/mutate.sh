#!/usr/bin/env bash
# Mutation campaign for cloud-email-archive's safety gates.
#
# Standard (see docs/arc42 + README Testing): a mutation must COMPILE, EXECUTE
# the mutated code path, and then FAIL its targeted test — that is a "kill".
# A mutation that breaks the build is INVALID, not a kill. A mutation whose
# test still passes means the test suite tolerates a weakened safety gate —
# the worst outcome, reported as SURVIVED.
#
# Usage:  scripts/mutate.sh [M-ids...]     (default: all)
#         scripts/mutate.sh M1 M6
set -u
cd "$(dirname "$0")/.."
GO=${GO:-go}

# dirty-tree guard: restoration is `git checkout -- <file>`, so ANY uncommitted
# change in the mutated files would be silently DESTROYED (this has actually
# eaten a feature branch once — hence the hard stop).
DIRTY=$(git status --porcelain -- internal/app/expire.go internal/app/sync.go internal/app/main.go internal/app/lock.go)
if [ -n "$DIRTY" ]; then
    echo "refusing to run: mutation targets have uncommitted changes" >&2
    echo "$DIRTY" >&2
    echo "commit (or stash) first — the script restores targets via git checkout" >&2
    exit 2
fi

# toolchain check: the script needs a go that can build THIS module (go.mod
# go-directive). Falls back to /usr/local/go/bin/go when the system go is too
# old (common on dev boxes with a distro go alongside the upstream toolchain).
if ! "$GO" build ./... >/dev/null 2>&1; then
    if [ -x /usr/local/go/bin/go ] && /usr/local/go/bin/go build ./... >/dev/null 2>&1; then
        GO=/usr/local/go/bin/go
    else
        echo "no working toolchain: need go $(grep '^go ' go.mod | awk '{print $2}') on PATH" >&2
        exit 2
    fi
fi

run_mutation() { # id file old new test_regex
    local id=$1 file=$2 old=$3 new=$4 regex=$5
    python3 - "$file" "$old" "$new" <<'EOF' || { echo "$id  INVALID (pattern not found)"; result=2; return; }
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(p).read()
assert src.count(old) == 1, f"pattern not unique/found in {p}"
open(p, "w").write(src.replace(old, new))
EOF
    if "$GO" build ./... >/dev/null 2>&1; then
        if "$GO" test -count=1 -run "$regex" ./internal/app >/dev/null 2>&1; then
            echo "$id  SURVIVED  (test still passes — weakened gate not caught!)"
            result=1
        else
            echo "$id  killed"
        fi
    else
        echo "$id  INVALID (mutation breaks the build — must execute instead)"
        result=2
    fi
    git checkout -- "$file"
}

result=0

M1='never-synced guard skipped (expire would run on folders without state)'
run_mutation M1 internal/app/expire.go \
    'if fs.UIDValidity == 0 {' \
    'if false && fs.UIDValidity == 0 {' \
    'TestExpireSkipsNeverSyncedFolder'

M2='UIDVALIDITY-changed guard skipped (stale UIDs would be deleted)'
run_mutation M2 internal/app/expire.go \
    'if fs.UIDValidity != sel.UIDValidity {' \
    'if false && fs.UIDValidity != sel.UIDValidity {' \
    'TestExpireSkipsUIDValidityChanged'

M3='INTERNALDATE window guard skipped (server drift deletes wrong mail)'
run_mutation M3 internal/app/expire.go \
    'if !internal.Before(cutoff) {' \
    'if false && !internal.Before(cutoff) {' \
    'TestExpireCutoffBoundaryExclusive'

M4='truncation guard in proveHoldings dropped (partial proof accepted)'
run_mutation M4 internal/app/expire.go \
    'if err == nil && item.Literal.Size() != int64(len(b)) {' \
    'if err == nil && false && item.Literal.Size() != int64(len(b)) {' \
    'TestExpireProofFetchTruncated'

M5='truncation guard in fetchAndArchive dropped (partial literal archived)'
run_mutation M5 internal/app/sync.go \
    'if err == nil && item.Literal.Size() != int64(len(b)) {' \
    'if err == nil && false && item.Literal.Size() != int64(len(b)) {' \
    'TestSyncTruncatedLiteralGuard'

M6='archiveHolds weakened (unproven mail counts as held, gets deleted)'
run_mutation M6 internal/app/expire.go \
    'return bytes.Equal(decSum[:], sum[:]), nil' \
    'return bytes.Equal(decSum[:], sum[:]) || true, nil' \
    'TestExpireBlobContentMismatchNotProven'

M7='flock error ignored (second instance may corrupt state)'
run_mutation M7 internal/app/lock.go \
    'if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {' \
    'if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); false && err != nil {' \
    'TestInstanceLockBlocksSecondWriter'

M8='dry-run default flipped to delete (expire without -do deletes!)'
run_mutation M8 internal/app/expire.go \
    'doIt := fs.Bool("do", false, "actually delete on the server (default: dry run)")' \
    'doIt := fs.Bool("do", true, "actually delete on the server (default: dry run)")' \
    'TestExpireDryRunDoesNotDelete'

echo
case "$result" in
0) echo "all mutations killed — safety gates are test-enforced" ;;
1) echo "SURVIVED mutations above need stronger tests" ;;
*) echo "INVALID mutations above — the campaign itself needs fixing" ;;
esac
exit "$result"
