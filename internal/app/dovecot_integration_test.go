//go:build integration

// Real-server integration tier. Everything else in this suite runs against
// go-imap's in-memory server — the same code family as the client, so
// implementation blind spots can hide on both sides simultaneously (beta.9's
// EOF-as-literal-end bug was exactly such a blind spot). This tier runs the
// full sync → verify → expire flow against Dovecot in Docker, the project's
// documented target server, exercising FOREIGN implementations of the
// machinery the tool depends on: UIDPLUS (UID EXPUNGE), server-side
// SEARCH BEFORE, INTERNALDATE round-trips across timezones, and tagged
// reply conventions.
//
// Requires docker with the dovecot/dovecot image (pulled on first run).
// Skipped automatically when docker is not on PATH. The container is bound
// to 127.0.0.1 on an ephemeral port and removed on test end.
//
// Run:	go test -tags integration -run TestDovecot -v

package app

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

const dovecotImage = "dovecot/dovecot:latest"

// The proven dovecot 2.4 config for a plaintext, loopback-only test server.
// 2.4 renamed most 2.3 settings (mail_location -> mail_driver/mail_path,
// passdb blocks need filter names, auth_allow_cleartext replaced
// disable_plaintext_auth, dovecot_storage_version is mandatory).
const dovecotConf = `dovecot_config_version = 2.4.3
dovecot_storage_version = 2.4.3
base_dir = /run/dovecot
state_dir = /run/dovecot
default_internal_user = vmail
default_login_user = vmail
protocols = imap
listen = *
ssl = no
auth_mechanisms = plain login
auth_allow_cleartext = yes
mail_driver = maildir
mail_path = ~/mail
mail_home = /srv/vmail/%{user | lower}
mail_uid = vmail
mail_gid = vmail
first_valid_uid = 500
log_path = /dev/stdout
passdb passwd-file {
  passdb_driver = passwd-file
  passwd_file_path = /run/dovecot/users
}
userdb passwd-file {
  userdb_driver = passwd-file
  passwd_file_path = /run/dovecot/users
}
`

// The image runs master as root but ships /etc/passwd without the system
// users compiled-in dovecot defaults expect (dovenull, dovecot) — augment a
// copy extracted from the image itself, so version drift stays visible.
const passwdAdds = "dovenull:x:110:65534:Dovecot login user:/nonexistent:/bin/false\ndovecot:x:111:65534:Dovecot unprivileged user:/nonexistent:/bin/false\n"
const groupAdds = "dovenull:x:110:\ndovecot:x:111:\n"

func dockerRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func startDovecot(t *testing.T) int {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH — real-server tier unavailable")
	}

	dir := t.TempDir()

	// extract the image's /etc/passwd and /etc/group, append the missing
	// dovecot system users
	id := strings.TrimSpace(dockerRun(t, "create", dovecotImage))
	defer dockerRun(t, "rm", id) //nolint:errcheck
	dockerRun(t, "cp", id+":/etc/passwd", filepath.Join(dir, "passwd"))
	dockerRun(t, "cp", id+":/etc/group", filepath.Join(dir, "group"))
	appendFile(filepath.Join(dir, "passwd"), passwdAdds)
	appendFile(filepath.Join(dir, "group"), groupAdds)

	if err := os.WriteFile(filepath.Join(dir, "dovecot.conf"), []byte(dovecotConf), 0o600); err != nil {
		t.Fatal(err)
	}
	// password file for testuser/testpw (uid/gid of the image's vmail user);
	// auth workers run as the dovecot system user (uid 111) — the file must
	// be group/other readable, not 0600
	users := "testuser:{PLAIN}testpw:1000:1000::/srv/vmail/testuser::\n"
	if err := os.WriteFile(filepath.Join(dir, "users"), []byte(users), 0o644); err != nil {
		t.Fatal(err)
	}

	name := "cea-dovecot-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	dockerRun(t, "rm", "-f", name) // stale leftovers from a crashed run
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "logs", name).CombinedOutput(); err == nil {
			t.Logf("--- dovecot logs ---\n%s", out)
		}
		exec.Command("docker", "rm", "-f", name).Run() //nolint:errcheck
	})

	dockerRun(t, "run", "-d", "--name", name, "--user", "root",
		"-v", filepath.Join(dir, "dovecot.conf")+":/etc/dovecot/dovecot.conf:ro",
		"-v", filepath.Join(dir, "users")+":/run/dovecot/users:ro",
		"-v", filepath.Join(dir, "passwd")+":/etc/passwd:ro",
		"-v", filepath.Join(dir, "group")+":/etc/group:ro",
		"-p", "127.0.0.1::143",
		dovecotImage)

	portOut := dockerRun(t, "port", name, "143/tcp")
	fields := strings.Fields(strings.TrimSpace(portOut))
	if len(fields) == 0 || !strings.Contains(fields[len(fields)-1], ":") {
		t.Fatalf("cannot parse docker port output: %q", portOut)
	}
	port, err := strconv.Atoi(fields[len(fields)-1][strings.LastIndex(fields[len(fields)-1], ":")+1:])
	if err != nil {
		t.Fatalf("cannot parse port from %q: %v", portOut, err)
	}

	// wait for the greeting; the image takes a few seconds on first start
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
			buf := make([]byte, 512)
			n, _ := conn.Read(buf)
			conn.Close() //nolint:errcheck
			if strings.Contains(string(buf[:n]), "OK") {
				return port
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("dovecot never became ready on port %d", port)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func appendFile(path, s string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()  //nolint:errcheck
	f.WriteString(s) //nolint:errcheck
}

// dovecotDial logs in as testuser; every IMAP interaction in this tier
// goes through the same client library the tool itself uses.
func dovecotDial(t *testing.T, port int) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(fmt.Sprintf("127.0.0.1:%d", port), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := c.Login("testuser", "testpw").Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	return c
}

// dovecotAppend delivers a message with an explicit INTERNALDATE — the
// same mechanism real users' servers apply on message arrival.
func dovecotAppend(t *testing.T, c *imapclient.Client, mailbox, raw string, at time.Time) imap.UID {
	t.Helper()
	cmd := c.Append(mailbox, int64(len(raw)), &imap.AppendOptions{Time: at})
	if _, err := cmd.Write([]byte(raw)); err != nil {
		t.Fatalf("append write: %v", err)
	}
	if err := cmd.Close(); err != nil { // terminate the literal, end the command
		t.Fatalf("append close: %v", err)
	}
	data, err := cmd.Wait()
	if err != nil {
		t.Fatalf("append to %s: %v", mailbox, err)
	}
	if data.UID == 0 {
		t.Fatalf("append to %s returned no UIDPLUS UID", mailbox)
	}
	return data.UID
}

func dovecotCount(t *testing.T, c *imapclient.Client, mailbox string) int {
	t.Helper()
	sel, err := c.Select(mailbox, nil).Wait()
	if err != nil {
		t.Fatalf("select %s: %v", mailbox, err)
	}
	return int(sel.NumMessages)
}

func TestDovecotIntegration(t *testing.T) {
	port := startDovecot(t)

	c := dovecotDial(t, port)
	defer func() { c.Logout().Wait() }() //nolint:errcheck

	// foreign-server checklist: INBOX gets the expirable corpus, a second
	// mailbox proves deletion stays scoped to configured folders
	if err := c.Create("Archive", nil).Wait(); err != nil {
		t.Fatalf("create Archive: %v", err)
	}
	mail := func(subj string) string {
		return fmt.Sprintf("From: a@x.de\r\nSubject: %s\r\n\r\n%s body\r\n", subj, subj)
	}
	dovecotAppend(t, c, "INBOX", mail("twentytwenty"), time.Date(2020, 3, 1, 12, 0, 0, 0, time.UTC))
	dovecotAppend(t, c, "INBOX", mail("twentytwentyone"), time.Date(2021, 6, 15, 8, 30, 0, 0, time.UTC))
	dovecotAppend(t, c, "INBOX", mail("twentyeighteen"), time.Date(2018, 11, 2, 23, 59, 0, 0, time.UTC))
	dovecotAppend(t, c, "Archive", mail("untouchable"), time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC))

	env := syncTestEnv(t, port, "test", []string{"INBOX"})
	tomorrow := time.Now().AddDate(0, 0, 2).Format("2006-01-02") // date-only cutoff: everything seeded is older

	// sync against a foreign server
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit = %d", code)
	}
	st := env.cfg(t).StateFile
	state := readStateFor(t, st, "test", "INBOX")
	if len(state.UIDs) != 3 {
		t.Fatalf("state has %d UIDs, want 3 (%v)", len(state.UIDs), state.UIDs)
	}

	// verify restores all three byte-identically from blobs alone
	if code := run([]string{"verify", "-config", env.cfgPath}); code != 0 {
		t.Fatalf("verify exit = %d", code)
	}

	// dry run: report only, touch nothing (the report goes to real stdout)
	stdout := captureStdout(t, func() {
		if code := run([]string{"expire", "-config", env.cfgPath, "-before", tomorrow}); code != 0 {
			t.Fatalf("expire dry-run exit = %d", code)
		}
	})
	if !strings.Contains(stdout, "3 of 3") {
		t.Fatalf("dry run must scope all 3 messages, got: %q", stdout)
	}
	if n := dovecotCount(t, c, "INBOX"); n != 3 {
		t.Fatalf("dry run deleted mail: %d left, want 3", n)
	}

	// the deletion itself: UID STORE \Deleted + UID EXPUNGE (UIDPLUS) on a
	// real server
	if code := runExpire(t, env.cfgPath, "-before", tomorrow, "-do"); code != 0 {
		t.Fatalf("expire -do exit = %d", code)
	}
	if n := dovecotCount(t, c, "INBOX"); n != 0 {
		t.Fatalf("expire -do left %d messages, want 0", n)
	}
	if n := dovecotCount(t, c, "Archive"); n != 1 {
		t.Fatalf("Archive mailbox must be untouched: %d messages, want 1", n)
	}

	// the deleted mail stays restorable from the append-only archive
	if code := run([]string{"verify", "-config", env.cfgPath}); code != 0 {
		t.Fatalf("verify after expire exit = %d", code)
	}
	assertBlobCount(t, env.arc, 3)

	// resync: INBOX is empty server-side, state must converge
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("post-expire sync exit = %d", code)
	}
	state = readStateFor(t, st, "test", "INBOX")
	if len(state.UIDs) != 0 {
		t.Fatalf("state must be pruned to the empty folder, got %v", state.UIDs)
	}
	if code := run([]string{"verify", "-config", env.cfgPath}); code != 0 {
		t.Fatalf("final verify exit = %d", code)
	}
}

// readStateFor reads one folder's state entry (the JSON schema lives in
// state.go; tests only read it through the loader to stay format-agnostic).
func readStateFor(t *testing.T, path, account, folder string) *FolderState {
	t.Helper()
	st, err := loadState(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	fs := st.Accounts[account][folder]
	if fs == nil {
		t.Fatalf("state has no entry for %s/%s", account, folder)
	}
	return fs
}
