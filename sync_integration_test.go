package main

// End-to-end sync tests against an in-process IMAP server (go-imap's
// imapmemserver). They exercise the production path: login → list/select →
// enumerate UIDs → fetch bodies (peek) → encrypted blobs, plus incremental
// re-sync via state and the CLI command around it.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

type lit struct{ *strings.Reader }

func (l lit) Size() int64 { return int64(l.Len()) }

// startMemIMAP spins up an in-process IMAP server with one user (INBOX) and
// returns the user handle (for seeding) and the listening port.
func startMemIMAP(t *testing.T, user, pass string) (*imapmemserver.User, int) {
	t.Helper()
	mem := imapmemserver.New()
	u := imapmemserver.NewUser(user, pass)
	if err := u.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	mem.AddUser(u)
	server := imapserver.New(&imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		InsecureAuth: true,
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {},
			imap.CapIMAP4rev2: {},
		},
	})
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		ln.Close()
	})
	go server.Serve(ln)
	return u, ln.Addr().(*net.TCPAddr).Port
}

func seedMail(t *testing.T, u *imapmemserver.User, folder, raw string) {
	t.Helper()
	if _, err := u.Append(folder, lit{strings.NewReader(raw)}, &imap.AppendOptions{}); err != nil {
		t.Fatal(err)
	}
}

// syncTestEnv builds a config file around a running memserver and returns the
// test environment (with an open archive handle).
func syncTestEnv(t *testing.T, port int, accountName string, folders []string) *testEnv {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	archiveDir := filepath.Join(dir, "archive")
	statePath := filepath.Join(dir, "state.json")
	cfgPath := filepath.Join(dir, "config.toml")

	captureStdout(t, func() {
		if err := writeNewKey(keyPath); err != nil {
			t.Fatal(err)
		}
	})
	foldersTOML := `folders = ["*"]`
	if folders != nil {
		quoted := make([]string, len(folders))
		for i, f := range folders {
			quoted[i] = fmt.Sprintf("%q", f)
		}
		foldersTOML = "folders = [" + strings.Join(quoted, ", ") + "]"
	}
	body := fmt.Sprintf(`archive_dir = %q
key_file = %q
state_file = %q

[[accounts]]
name = %q
host = "127.0.0.1"
port = %d
security = "none"
user = "testuser"
password = "testpw"
%s
`, archiveDir, keyPath, statePath, accountName, port, foldersTOML)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := loadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{dir: dir, cfgPath: cfgPath, arc: newArchive(archiveDir, id)}
}

func runSync(t *testing.T, cfgPath string) int {
	t.Helper()
	var code int
	captureStdout(t, func() {
		code = run([]string{"sync", "-config", cfgPath})
	})
	return code
}

// The original end-to-end test: first sync fetches everything, second is a
// no-op, third fetches exactly the new message.
func TestSyncAccountIntegration(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	msg1 := "From: a@x.de\r\nSubject: eins\r\n\r\nbody eins\r\n"
	msg2 := "From: b@x.de\r\nSubject: zwei\r\n\r\nbody zwei\r\n"
	seedMail(t, u, "INBOX", msg1)
	seedMail(t, u, "INBOX", msg2)

	env := syncTestEnv(t, port, "test", nil)
	cfg := env.cfg(t)
	st := env.state(t) // one state instance across all three syncs

	// --- first sync: 2 blobs, decrypted content matches ---
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog()); err != nil {
		t.Fatal(err)
	}
	blobs, err := env.arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 2 {
		t.Fatalf("expected 2 blobs after first sync, got %d", len(blobs))
	}
	got := map[string]bool{}
	for _, b := range blobs {
		raw, err := env.arc.get(b.name)
		if err != nil {
			t.Fatal(err)
		}
		got[string(raw)] = true
	}
	if !got[msg1] || !got[msg2] {
		t.Fatalf("decrypted content mismatch: %v", got)
	}

	// --- second sync: nothing new → still 2 blobs ---
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog()); err != nil {
		t.Fatal(err)
	}
	if blobs, _ := env.arc.blobs(); len(blobs) != 2 {
		t.Fatalf("expected still 2 blobs after no-op sync, got %d", len(blobs))
	}

	// --- third sync with one new message → exactly 3 blobs ---
	seedMail(t, u, "INBOX", "From: c@x.de\r\nSubject: drei\r\n\r\nbody drei\r\n")
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog()); err != nil {
		t.Fatal(err)
	}
	if blobs, _ := env.arc.blobs(); len(blobs) != 3 {
		t.Fatalf("expected 3 blobs after incremental sync, got %d", len(blobs))
	}
}

func TestCmdSyncEndToEnd(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: eins\r\n\r\nbody eins\r\n")
	seedMail(t, u, "INBOX", "From: b@x.de\r\nSubject: zwei\r\n\r\nbody zwei\r\n")

	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit code %d", code)
	}
	blobs, err := env.arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 2 {
		t.Fatalf("expected 2 blobs after sync, got %d", len(blobs))
	}
	if _, err := os.Stat(filepath.Join(env.dir, "state.json")); err != nil {
		t.Fatalf("state.json not written: %v", err)
	}
}

// A failing account must yield a non-zero exit even though state is still
// saved — this is what makes cron alerting possible.
func TestCmdSyncFailedAccountNonZeroExit(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	cfgPath := filepath.Join(dir, "config.toml")
	captureStdout(t, func() {
		if err := writeNewKey(keyPath); err != nil {
			t.Fatal(err)
		}
	})
	body := fmt.Sprintf(`archive_dir = %q
key_file = %q
state_file = %q

[[accounts]]
name = "dead"
host = "127.0.0.1"
port = 1
security = "none"
user = "x"
password = "y"
`, filepath.Join(dir, "archive"), keyPath, filepath.Join(dir, "state.json"))
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut string
	var code int
	out = captureStdout(t, func() {
		errOut = captureStream(t, &os.Stderr, func() {
			code = run([]string{"sync", "-config", cfgPath})
		})
	})
	if code != 1 {
		t.Fatalf("sync with dead account must exit 1, got %d\nstdout: %s", code, out)
	}
	if !strings.Contains(errOut, "account dead") {
		t.Errorf("error output must name the failing account:\n%s", errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Errorf("state must be saved even on account failure: %v", err)
	}
}

func TestSyncFolderFilter(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	if err := u.Create("Archiv", nil); err != nil {
		t.Fatal(err)
	}
	seedMail(t, u, "INBOX", "From: inbox@x.de\r\nSubject: inbox only\r\n\r\ninbox body\r\n")
	seedMail(t, u, "Archiv", "From: archiv@x.de\r\nSubject: must be skipped\r\n\r\narchiv body\r\n")

	env := syncTestEnv(t, port, "test", []string{"INBOX"}) // only INBOX configured
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit %d", code)
	}

	seen := 0
	if err := env.arc.walk("", func(r msgRef) error {
		seen++
		if strings.Contains(string(r.raw), "archiv body") {
			t.Error("folder filter leaked: Archiv message was archived")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("expected exactly 1 archived message (INBOX), got %d", seen)
	}
}

// Account names with underscores must survive the full pipeline: blob naming,
// on-disk storage, and the -account filter of the read commands.
func TestSyncUnderscoredAccount(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: u@x.de\r\nSubject: underscore\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "uni_mail", nil)

	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit %d", code)
	}
	blobs, err := env.arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 1 {
		t.Fatalf("expected 1 blob, got %d", len(blobs))
	}
	if accountOf(blobs[0].name) != "uni_mail" {
		t.Fatalf("accountOf roundtrip broken: %q", blobs[0].name)
	}

	var out string
	var listErr error
	out = captureStdout(t, func() {
		listErr = cmdList([]string{"-config", env.cfgPath, "-account", "uni_mail"})
	})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if !strings.Contains(out, "underscore") {
		t.Errorf("list -account uni_mail found nothing:\n%s", out)
	}
}

// Plaintext IMAP (security = "none") must produce an explicit warning.
func TestSyncSecurityNoneWarns(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: w@x.de\r\nSubject: warn\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	cfg, err := loadConfig(env.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := loadState(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "security=none") {
		t.Errorf("missing plaintext-IMAP warning in logs:\n%s", buf.String())
	}
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

// nopWriter swallows log noise.
type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// Wrong credentials must surface as a sync error naming the login failure.
func TestSyncWrongPassword(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: x@x.de\r\nSubject: secret\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)

	// sabotage the password in the written config
	body, err := os.ReadFile(env.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.cfgPath, bytes.ReplaceAll(body, []byte(`password = "testpw"`), []byte(`password = "wrong"`)), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := env.cfg(t)
	st := env.state(t)
	_, err = syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog())
	if err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("want login error, got %v", err)
	}
	// nothing archived from the failed attempt
	if blobs, _ := env.arc.blobs(); len(blobs) != 0 {
		t.Fatalf("failed sync must not archive, got %d blobs", len(blobs))
	}
}

// A UIDVALIDITY change (mailbox reset on the server) must trigger a clean
// re-fetch: state is discarded for the folder and UIDs are rebuilt.
func TestSyncUIDValidityReset(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: r@x.de\r\nSubject: reset\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)
	cfg := env.cfg(t)
	st := env.state(t) // one in-memory state across both syncs

	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog()); err != nil {
		t.Fatal(err)
	}
	fs := st.folder("test", "INBOX")
	good := fs.UIDValidity
	if good == 0 {
		t.Fatal("first sync must record UIDValidity")
	}
	// simulate the server having rebuilt the mailbox (new UIDValidity)
	fs.UIDValidity = good + 1
	if err := st.save(cfg.StateFile); err != nil {
		t.Fatal(err)
	}

	// re-sync: clean re-fetch, no error, state healed back to the real UIDValidity
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog()); err != nil {
		t.Fatal(err)
	}
	healed := st.folder("test", "INBOX")
	if healed.UIDValidity != good {
		t.Fatalf("UIDValidity not healed: got %d, want %d", healed.UIDValidity, good)
	}
	if len(healed.UIDs) == 0 {
		t.Fatal("UIDs must be re-recorded after reset")
	}
	// append-only: the reset refetch dedups against existing blobs
	if blobs, _ := env.arc.blobs(); len(blobs) != 1 {
		t.Fatalf("reset re-fetch must dedup, got %d blobs", len(blobs))
	}
}

// startMemIMAPHook starts the in-memory IMAP server with a session decorator,
// letting tests inject selective failures (e.g. SELECT of one folder).
func startMemIMAPHook(t *testing.T, user, pass string, hook func(imapserver.Session) imapserver.Session) (*imapmemserver.User, int) {
	t.Helper()
	mem := imapmemserver.New()
	u := imapmemserver.NewUser(user, pass)
	if err := u.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	mem.AddUser(u)
	server := imapserver.New(&imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return hook(mem.NewSession()), nil, nil
		},
		InsecureAuth: true,
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {},
			imap.CapIMAP4rev2: {},
		},
	})
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		ln.Close()
	})
	go server.Serve(ln)
	return u, ln.Addr().(*net.TCPAddr).Port
}

// A configured folder that is not on the server must fail the sync (and must
// not silently archive nothing) — it means the mailbox was renamed or deleted.
func TestSyncAccountMissingFolderErrors(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: present\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", []string{"Ghost"})
	cfg := env.cfg(t)

	_, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, env.state(t), quietLog())
	if err == nil || !strings.Contains(err.Error(), "Ghost") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want missing-folder error, got %v", err)
	}
	// the present-but-unconfigured INBOX must NOT have been synced
	if blobs, _ := env.arc.blobs(); len(blobs) != 0 {
		t.Fatalf("unconfigured INBOX must not be archived, got %d blobs", len(blobs))
	}
}

// brokenSelectSession fails SELECT for one specific folder, simulating a
// server-side error, while everything else behaves normally.
type brokenSelectSession struct {
	// embed the full rev2 capability set so the server's interface
	// assertions keep passing; only Select is overridden
	imapserver.SessionIMAP4rev2
	fail string
}

func (s *brokenSelectSession) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	if mailbox == s.fail {
		return nil, errors.New("simulated select failure")
	}
	return s.SessionIMAP4rev2.Select(mailbox, options)
}

// One broken folder must not abort the healthy folder's sync, but must fail
// the account (joined error) so cron alerting sees it.
func TestSyncAccountFolderFailureJoined(t *testing.T) {
	u, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &brokenSelectSession{SessionIMAP4rev2: s.(imapserver.SessionIMAP4rev2), fail: "Broken"}
	})
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: healthy\r\n\r\nbody\r\n")
	// Broken must EXIST on the server, otherwise selectFolders routes it to
	// the missing-folder path and the SELECT failure never triggers
	if err := u.Create("Broken", nil); err != nil {
		t.Fatal(err)
	}
	env := syncTestEnv(t, port, "test", []string{"INBOX", "Broken"})
	cfg := env.cfg(t)
	st := env.state(t) // one in-memory instance; raw syncAccount never saves

	_, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog())
	if err == nil || !strings.Contains(err.Error(), "Broken") {
		t.Fatalf("want joined folder-failure error naming Broken, got %v", err)
	}
	// the healthy INBOX must still have been archived despite Broken failing
	blobs, _ := env.arc.blobs()
	if len(blobs) != 1 {
		t.Fatalf("healthy folder must still sync, got %d blobs", len(blobs))
	}
	if len(st.folder("test", "INBOX").UIDs) != 1 {
		t.Fatal("healthy folder UIDs must be recorded despite sibling failure")
	}
}

// A put failure mid-sync must surface as an account error (fetched-but-not-
// stored mail must not be remembered, or the next sync would skip it).
func TestSyncPutFailureSurfaces(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: lost\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", []string{"INBOX"})
	cfg := env.cfg(t)

	failArc := newArchive(env.dir, testID(t))
	failArc.newWriter = func(io.Writer, ...age.Recipient) (io.WriteCloser, error) {
		return nil, errors.New("simulated encrypt failure")
	}
	_, err := syncAccount(cfg, &cfg.Accounts[0], failArc, env.state(t), quietLog())
	if err == nil || !strings.Contains(err.Error(), "simulated encrypt failure") {
		t.Fatalf("want put error to fail the account, got %v", err)
	}
	// no tmp leftovers from the failed put
	entries, _ := os.ReadDir(env.dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("failed sync left %s behind", e.Name())
		}
	}
}

// An empty folder must sync cleanly (enumerate early-returns) and record its
// UIDVALIDITY so later changes are detected.
func TestSyncEmptyFolder(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: one\r\n\r\nbody\r\n")
	if err := u.Create("Leer", nil); err != nil {
		t.Fatal(err)
	}
	env := syncTestEnv(t, port, "test", []string{"INBOX", "Leer"})
	cfg := env.cfg(t)
	st := env.state(t)

	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog()); err != nil {
		t.Fatal(err)
	}
	if st.folder("test", "Leer").UIDValidity == 0 {
		t.Error("empty folder must record UIDVALIDITY")
	}
	if len(st.folder("test", "Leer").UIDs) != 0 {
		t.Error("empty folder must have no UIDs")
	}
}

// hookSession lets tests inject faults (or rewritten responses) into specific
// IMAP commands while delegating everything else to the real session.
type hookSession struct {
	imapserver.Session
	fetch   func(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error
	list    func(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error
	selectM func(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error)
}

func (s *hookSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	if s.fetch != nil {
		return s.fetch(w, numSet, options)
	}
	return s.Session.Fetch(w, numSet, options)
}

func (s *hookSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if s.list != nil {
		return s.list(w, ref, patterns, options)
	}
	return s.Session.List(w, ref, patterns, options)
}

func (s *hookSession) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	if s.selectM != nil {
		return s.selectM(mailbox, options)
	}
	return s.Session.Select(mailbox, options)
}

// The server type-asserts optional interfaces (SessionIMAP4rev2 etc.) on the
// session — an embedded interface value would hide them from the assertions,
// so they are forwarded explicitly.
func (s *hookSession) Namespace() (*imap.NamespaceData, error) {
	return s.Session.(imapserver.SessionNamespace).Namespace()
}

func (s *hookSession) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	return s.Session.(imapserver.SessionMove).Move(w, numSet, dest)
}

// A FETCH response with a zero-length literal must be skipped (empty body),
// not archived, and must not fail the sync.
func TestFetchEmptyBodySkipped(t *testing.T) {
	quietLog()
	u, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, fetch: func(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
			rw := w.CreateMessage(1)
			rw.WriteUID(1)
			wc := rw.WriteBodySection(&imap.FetchItemBodySection{Peek: true}, 0)
			wc.Close() //nolint:errcheck
			return rw.Close()
		}}
	})
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: real\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("empty-body fetch failed the sync: exit %d", code)
	}
	assertBlobCount(t, env.arc, 0)
}

// A server that answers the body fetch WITHOUT a UID: go-imap v2 beta.9
// discards such responses unilaterally (a UID-less FETCH response can never
// match the pending UID FETCH command), so the sync archives nothing and
// succeeds — the message simply stays "new" for the next run. That client
// behavior also makes fetchAndArchive's uid==0 guard unreachable against
// beta.9; it stays as defense against future client versions.
func TestFetchUIDLessResponseDiscarded(t *testing.T) {
	quietLog()
	u, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, fetch: func(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
			if len(options.BodySection) == 0 {
				return s.Fetch(w, numSet, options)
			}
			rw := w.CreateMessage(1)
			rw.WriteFlags(nil)
			raw := "From: a@x.de\r\nSubject: no-uid\r\n\r\nbody\r\n"
			wc := rw.WriteBodySection(&imap.FetchItemBodySection{Peek: true}, int64(len(raw)))
			wc.Write([]byte(raw)) //nolint:errcheck
			wc.Close()            //nolint:errcheck
			return rw.Close()
		}}
	})
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: real\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("exit = %d, want 0 (UID-less response is discarded, not fatal)", code)
	}
	if blobs, _ := env.arc.blobs(); len(blobs) != 0 {
		t.Fatalf("UID-less response archived anyway: %d blob(s)", len(blobs))
	}
}

func (c *cappedConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *cappedConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

// cappedConn limits how far into the future the client may push socket
// deadlines, so stuck reads surface in seconds instead of literalReadTimeout.
type cappedConn struct {
	net.Conn
	cap time.Duration
}

func (c *cappedConn) SetDeadline(t time.Time) error {
	if t.IsZero() || time.Until(t) <= c.cap {
		return c.Conn.SetDeadline(t)
	}
	return c.Conn.SetDeadline(time.Now().Add(c.cap))
}

// A literal that aborts mid-stream (server crash, network drop) must fail
// the sync loudly — a silently truncated archive is worse than a failed run.
func TestFetchMidLiteralAbort(t *testing.T) {
	quietLog()
	u, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, fetch: func(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
			rw := w.CreateMessage(1)
			rw.WriteUID(1)
			wc := rw.WriteBodySection(&imap.FetchItemBodySection{Peek: true}, 500)
			wc.Write([]byte("truncat")) //nolint:errcheck
			wc.Close()                  //nolint:errcheck
			return rw.Close()           // promises 500 bytes, sent 7 — client must error
		}}
	})
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: real\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)
	// run the client path over a capped-deadline conn: the truncated literal
	// then surfaces as a read timeout within seconds (mirrors a real
	// deployment's network deadline) instead of the client's 5-minute
	// literalReadTimeout, which would overwrite any fixed deadline we set
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := imapclient.New(&cappedConn{Conn: conn, cap: 3 * time.Second}, nil)
	if err := c.Login("testuser", "testpw").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	cmd := c.Fetch(imap.UIDSetNum(1), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{{Peek: true}}})
	var litErr error
	for {
		msg := cmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if bs, ok := item.(imapclient.FetchItemDataBodySection); ok && bs.Literal != nil {
				_, litErr = io.ReadAll(bs.Literal)
			}
		}
	}
	// no cmd.Close here: the stream is desynced by the aborted literal and a
	// graceful close would block — tear the connection down instead
	if litErr == nil {
		t.Fatal("truncated literal read without error")
	}
	if blobs, _ := env.arc.blobs(); len(blobs) != 0 {
		t.Fatalf("truncated fetch archived data: %d blob(s)", len(blobs))
	}
	conn.Close() //nolint:errcheck
}

// \Noselect mailboxes (Dovecot hierarchy placeholders) must be filtered out
// of enumeration: selecting them always fails.
func TestSelectFoldersSkipsNoselect(t *testing.T) {
	quietLog()
	_, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, list: func(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
			if err := s.List(w, ref, patterns, options); err != nil {
				return err
			}
			return w.WriteList(&imap.ListData{
				Mailbox: "ArchiveTree/2024",
				Attrs:   []imap.MailboxAttr{imap.MailboxAttrNoSelect},
			})
		}}
	})
	c, err := dial(&Account{Name: "t", Host: "127.0.0.1", Port: port, Security: "none"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Logout() })
	if err := c.Login("testuser", "testpw").Wait(); err != nil {
		t.Fatal(err)
	}
	found, missing, err := selectFolders(c, &Account{Name: "test", Folders: []string{"*"}}, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if f == "ArchiveTree/2024" {
			t.Fatal("\\Noselect folder enumerated")
		}
	}
	// INBOX (selectable) must still be found
	if len(found) != 1 || found[0] != "INBOX" {
		t.Fatalf("found = %v, want [INBOX]", found)
	}
	if len(missing) != 0 {
		t.Fatalf("missing = %v, want none", missing)
	}
}

// A LIST command that errors mid-response must fail selectFolders (and thus
// the sync) — an incomplete folder inventory would silently skip mail.
func TestSelectFoldersListError(t *testing.T) {
	quietLog()
	_, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, list: func(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
			if err := s.List(w, ref, patterns, options); err != nil {
				return err
			}
			return errors.New("injected list fault")
		}}
	})
	c, err := dial(&Account{Name: "t", Host: "127.0.0.1", Port: port, Security: "none"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Logout() })
	if err := c.Login("testuser", "testpw").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectFolders(c, &Account{Name: "test", Folders: []string{"*"}}, quietLog()); err == nil {
		t.Fatal("list fault silently swallowed by selectFolders")
	}
}

// selectFolders failure must fail syncAccount (warn-free contract: folder
// enumeration is not optional).
func TestSyncSelectFoldersError(t *testing.T) {
	quietLog()
	_, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, list: func(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
			if err := s.List(w, ref, patterns, options); err != nil {
				return err
			}
			return errors.New("injected list fault")
		}}
	})
	env := syncTestEnv(t, port, "test", nil)
	cfg, err := loadConfig(env.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, &State{Accounts: map[string]map[string]*FolderState{}}, quietLog()); err == nil {
		t.Fatal("syncAccount swallowed selectFolders failure")
	}
}

// A folder that LISTS fine but fails SELECT (broken mailbox on the server)
// must fail the sync with the enumerate error naming the folder.
func TestSyncBrokenSelect(t *testing.T) {
	quietLog()
	_, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, selectM: func(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
			return nil, errors.New("injected select fault")
		}}
	})
	env := syncTestEnv(t, port, "test", []string{"INBOX"})
	cfg, err := loadConfig(env.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = syncAccount(cfg, &cfg.Accounts[0], env.arc, &State{Accounts: map[string]map[string]*FolderState{}}, quietLog())
	if err == nil || !strings.Contains(err.Error(), "select") || !strings.Contains(err.Error(), "INBOX") {
		t.Fatalf("want select error naming INBOX, got %v", err)
	}
}

// A folder that SELECTs fine but whose SEARCH fails must fail the sync with
// the enumerate error naming the folder (UID inventory incomplete).
func TestSyncBrokenSearch(t *testing.T) {
	quietLog()
	u, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		// enumerateUIDs fetches UIDs only (no body section) — fault exactly that
		return &hookSession{Session: s, fetch: func(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
			if len(options.BodySection) == 0 {
				return errors.New("injected enumerate fault")
			}
			return s.Fetch(w, numSet, options)
		}}
	})
	env := syncTestEnv(t, port, "test", []string{"INBOX"})
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: one\r\n\r\nbody\r\n")
	cfg, err := loadConfig(env.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = syncAccount(cfg, &cfg.Accounts[0], env.arc, &State{Accounts: map[string]map[string]*FolderState{}}, quietLog())
	if err == nil || !strings.Contains(err.Error(), "enumerate") || !strings.Contains(err.Error(), "INBOX") {
		t.Fatalf("want enumerate error naming INBOX, got %v", err)
	}
}

// A server that goes away mid-fetch (connection drop while the literal is
// still pending) must fail the sync loudly — a truncated archive is worse
// than a failed run. A raw TCP responder is used because the abort must be a
// real socket close: any in-band session error keeps the connection open and
// the client waits out its literal timeout instead of surfacing the drop.
func TestFetchConnDropMidLiteral(t *testing.T) {
	quietLog()
	if raceEnabled {
		t.Skip("go-imap v2 beta.9 client races on EOF-during-literal (reader goroutine resumes parsing while the app reads the literal) — upstream bug, not ours")
	}
	port := startRawAbortIMAP(t)
	env := syncTestEnv(t, port, "test", []string{"INBOX"})
	if code := runSync(t, env.cfgPath); code == 0 {
		t.Fatal("connection drop mid-fetch was silently swallowed")
	}
	if blobs, _ := env.arc.blobs(); len(blobs) != 0 {
		t.Fatalf("dropped fetch archived data: %d blob(s)", len(blobs))
	}
}

// startRawAbortIMAP serves just enough IMAP to reach a body fetch: greeting,
// LOGIN, LIST (one folder), SELECT (1 message, UIDVALIDITY), UID-only FETCH
// (honest), body FETCH (truncated literal, then the socket closes hard).
func startRawAbortIMAP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveRawAbortIMAP(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveRawAbortIMAP(c net.Conn) {
	defer c.Close() //nolint:errcheck
	buf := make([]byte, 4096)
	c.Write([]byte("* OK ready\r\n")) //nolint:errcheck
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		line := string(buf[:n])
		sp := strings.IndexByte(line, ' ')
		if sp <= 0 {
			continue
		}
		tag, rest := line[:sp], line[sp+1:]
		switch {
		case strings.HasPrefix(rest, "LOGIN"):
			c.Write([]byte(tag + " OK logged in\r\n")) //nolint:errcheck
		case strings.HasPrefix(rest, "LIST"):
			c.Write([]byte("* LIST () \"/\" \"INBOX\"\r\n" + tag + " OK done\r\n")) //nolint:errcheck
		case strings.HasPrefix(rest, "SELECT"), strings.HasPrefix(rest, "EXAMINE"): // syncFolder selects read-only
			c.Write([]byte("* 1 EXISTS\r\n* OK [UIDVALIDITY 42] uids\r\n" + tag + " OK selected\r\n")) //nolint:errcheck
		case strings.Contains(rest, "FETCH"): // plain FETCH and UID FETCH
			if strings.Contains(rest, "BODY") {
				// promise 500 bytes, send 7, drop — the client must error
				c.Write([]byte("* 1 FETCH (UID 1 BODY[] {500}\r\ntruncat")) //nolint:errcheck
				return
			}
			c.Write([]byte("* 1 FETCH (UID 1)\r\n" + tag + " OK done\r\n")) //nolint:errcheck
		default:
			c.Write([]byte(tag + " OK done\r\n")) //nolint:errcheck
		}
	}
}

// A server that serves a complete FETCH response but rejects the command
// completion (tagged NO) must fail the sync at cmd.Close — partial trust is
// no trust.
func TestFetchTaggedNO(t *testing.T) {
	quietLog()
	u, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, fetch: func(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
			if len(options.BodySection) == 0 {
				return s.Fetch(w, numSet, options)
			}
			rw := w.CreateMessage(1)
			rw.WriteUID(1)
			raw := "From: a@x.de\r\nSubject: complete\r\n\r\nbody\r\n"
			wc := rw.WriteBodySection(&imap.FetchItemBodySection{Peek: true}, int64(len(raw)))
			wc.Write([]byte(raw)) //nolint:errcheck
			wc.Close()            //nolint:errcheck
			if err := rw.Close(); err != nil {
				return err
			}
			return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "injected"}
		}}
	})
	seedMail(t, u, "INBOX", "From: a@x.de\r\nSubject: real\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code == 0 {
		t.Fatal("tagged NO on fetch completion was silently swallowed")
	}
	// the body itself arrived completely and is durably archived (put ran
	// before the completion arrived) — but the run FAILS because the UID was
	// never remembered, so the next sync re-fetches and dedup absorbs it.
	// Losing the notification would mean silently trusting an incomplete
	// fetch session.
	if blobs, _ := env.arc.blobs(); len(blobs) != 1 {
		t.Fatalf("complete blob lost by tagged NO: %d blob(s)", len(blobs))
	}
}
