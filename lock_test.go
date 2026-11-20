//go:build unix

package main

import (
	"strings"
	"testing"
)

// Two processes against one profile must not both proceed: the second
// writer refuses with a clear message while the lock is held, and the same
// command succeeds once it is free. (Mutation check: ignoring the flock
// error must fail this test.)
func TestInstanceLockBlocksSecondWriter(t *testing.T) {
	quietLog()
	env, _, _ := expireFixture(t)

	l, err := lockInstance(env.cfg(t).StateFile) // simulate instance #1
	if err != nil {
		t.Fatal(err)
	}

	var stderr string
	var code int
	stderr = captureStderr(t, func() {
		code = runSync(t, env.cfgPath)
	})
	if code == 0 {
		t.Fatal("second instance must exit non-zero while the lock is held")
	}
	if !strings.Contains(stderr, "another cloud-email-archive instance is running") {
		t.Fatalf("refusal must name the concurrent instance, got: %q", stderr)
	}

	if err := l.release(); err != nil {
		t.Fatal(err)
	}
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync after lock release exit = %d", code)
	}
}
