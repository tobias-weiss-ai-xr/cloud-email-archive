//go:build unix

package app

import (
	"fmt"
	"os"
	"syscall"
)

// instanceLock is an advisory single-writer lock for the state-mutating
// commands (sync, expire, index). Two concurrent runs against the same
// profile would otherwise last-writer-wins each other's state file and race
// on index segments; the archive itself is append-only and safe, but the
// derived state is not. list, search, extract and verify are read-only and
// lock-free.
//
// The lock lives next to the state file as "<state>.lock" and is never
// removed: unlinking a flock'd file would let a second process lock a fresh
// inode, silently defeating the lock. A leftover lock file after a crash is
// harmless — the flock is held on the open file description, not the path.
type instanceLock struct{ f *os.File }

func lockInstance(statePath string) (*instanceLock, error) {
	f, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", statePath+".lock", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close() //nolint:errcheck
		return nil, fmt.Errorf("another cloud-email-archive instance is running (lock busy: %s)", statePath+".lock")
	}
	return &instanceLock{f: f}, nil
}

func (l *instanceLock) release() error { return l.f.Close() }
