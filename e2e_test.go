package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// True-binary E2E: the in-process run() dispatch used everywhere else never
// exercises exec, argv, signal handling or real stdout/stderr pipes. This
// test builds the actual binary and drives it like a user would.
func TestE2EBinary(t *testing.T) {
	quietLog()
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	bin := filepath.Join(t.TempDir(), "cea")
	if out, err := exec.Command(goBin, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	execBin := func(args ...string) (int, string) {
		out, err := exec.Command(bin, args...).CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("exec %v: %v", args, err)
		}
		return code, string(out)
	}

	if code, out := execBin("version"); code != 0 || !strings.Contains(out, "cloud-email-archive") {
		t.Fatalf("version: exit=%d out=%q", code, out)
	}
	if code, out := execBin(); code != 2 || !strings.Contains(out, "Commands:") {
		t.Fatalf("no args: exit=%d out=%q", code, out)
	}

	env, _, _ := expireFixture(t)

	// real subprocess refusal: missing -before
	if code, out := execBin("expire", "-config", env.cfgPath); code == 0 || !strings.Contains(out, "requires -before") {
		t.Fatalf("expire w/o -before: exit=%d out=%q", code, out)
	}

	// the real binary talks to the live IMAP server and its own archive
	if code, out := execBin("sync", "-config", env.cfgPath); code != 0 {
		t.Fatalf("binary sync: exit=%d out=%q", code, out)
	}
	if code, out := execBin("verify", "-config", env.cfgPath); code != 0 || !strings.Contains(out, "3 ok, 0 failed") {
		t.Fatalf("binary verify: exit=%d out=%q", code, out)
	}
	if code, out := execBin("nonsense", "-config", env.cfgPath); code != 2 {
		t.Fatalf("unknown command: exit=%d out=%q", code, out)
	}
}
