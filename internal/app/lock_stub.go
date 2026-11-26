//go:build !unix

package app

// Non-Unix fallback: no advisory file locking available, so concurrent runs
// are simply unsafe (last-writer-wins on the state file). The single-writer
// rule is documented in the README.

type instanceLock struct{}

func lockInstance(statePath string) (*instanceLock, error) { return &instanceLock{}, nil }

func (l *instanceLock) release() error { return nil }
