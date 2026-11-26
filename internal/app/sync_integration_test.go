package app

// End-to-end sync tests against an in-process IMAP server (go-imap's
// imapmemserver). They exercise the production path: login → list/select →
// enumerate UIDs → fetch bodies (peek) → encrypted blobs, plus incremental
// re-sync via state and the CLI command around it.

import (
	"bufio"
	"sync/atomic"

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
	"github.com/BurntSushi/toml"
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
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog(), nil); err != nil {
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
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog(), nil); err != nil {
		t.Fatal(err)
	}
	if blobs, _ := env.arc.blobs(); len(blobs) != 2 {
		t.Fatalf("expected still 2 blobs after no-op sync, got %d", len(blobs))
	}

	// --- third sync with one new message → exactly 3 blobs ---
	seedMail(t, u, "INBOX", "From: c@x.de\r\nSubject: drei\r\n\r\nbody drei\r\n")
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog(), nil); err != nil {
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
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, log, nil); err != nil {
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
	_, err = syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog(), nil)
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

	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog(), nil); err != nil {
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
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog(), nil); err != nil {
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

	_, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, env.state(t), quietLog(), nil)
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

	_, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog(), nil)
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
	_, err := syncAccount(cfg, &cfg.Accounts[0], failArc, env.state(t), quietLog(), nil)
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

	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, st, quietLog(), nil); err != nil {
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
	store   func(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error
	expunge func(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error
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

func (s *hookSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	if s.store != nil {
		return s.store(w, numSet, flags, options)
	}
	return s.Session.Store(w, numSet, flags, options)
}

func (s *hookSession) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if s.expunge != nil {
		return s.expunge(w, uids)
	}
	return s.Session.Expunge(w, uids)
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
	if _, err := syncAccount(cfg, &cfg.Accounts[0], env.arc, &State{Accounts: map[string]map[string]*FolderState{}}, quietLog(), nil); err == nil {
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
	_, err = syncAccount(cfg, &cfg.Accounts[0], env.arc, &State{Accounts: map[string]map[string]*FolderState{}}, quietLog(), nil)
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
	_, err = syncAccount(cfg, &cfg.Accounts[0], env.arc, &State{Accounts: map[string]map[string]*FolderState{}}, quietLog(), nil)
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
	// line-based: the client may coalesce several commands into one TCP
	// segment; answering one command per Read() deadlocks both sides on the
	// unsent reply (seen as a rare full test-timeout hang)
	rd := bufio.NewReader(c)
	c.Write([]byte("* OK ready\r\n")) //nolint:errcheck
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
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

// ---------------------------------------------------------------------------
// expire: delete server-side mail the archive provably holds
// ---------------------------------------------------------------------------

// runExpire invokes the expire command the way a user would (capturing stdout
// so the dry-run report doesn't pollute test output).
func runExpire(t *testing.T, cfgPath string, extra ...string) int {
	t.Helper()
	var code int
	captureStdout(t, func() {
		code = run(append([]string{"expire", "-config", cfgPath}, extra...))
	})
	return code
}

// seedMailAt appends a message with an explicit INTERNALDATE (what -before
// and expire scope against).
func seedMailAt(t *testing.T, u *imapmemserver.User, folder, raw string, when time.Time) {
	t.Helper()
	if _, err := u.Append(folder, lit{strings.NewReader(raw)}, &imap.AppendOptions{Time: when}); err != nil {
		t.Fatal(err)
	}
}

// serverMessages counts messages currently in the memserver mailbox via a
// STATUS round-trip.
func serverMessages(t *testing.T, u *imapmemserver.User, folder string) int {
	t.Helper()
	data, err := u.Status(folder, &imap.StatusOptions{NumMessages: true})
	if err != nil {
		t.Fatal(err)
	}
	if data.NumMessages == nil {
		t.Fatal("STATUS did not report NumMessages")
	}
	return int(*data.NumMessages)
}

// expireFixture: memserver with one old (2020) and one old (2024) and one
// fresh message, all synced into the archive. Returns the env and user.
func expireFixture(t *testing.T) (*testEnv, *imapmemserver.User, int) {
	t.Helper()
	quietLog()
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMailAt(t, u, "INBOX", "From: old1@x.de\r\nSubject: old one\r\n\r\nbody1\r\n", time.Date(2020, 6, 1, 12, 0, 0, 0, time.Local))
	seedMailAt(t, u, "INBOX", "From: old2@x.de\r\nSubject: old two\r\n\r\nbody2\r\n", time.Date(2024, 3, 15, 12, 0, 0, 0, time.Local))
	seedMail(t, u, "INBOX", "From: fresh@x.de\r\nSubject: fresh\r\n\r\nfresh body\r\n")
	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit = %d", code)
	}
	assertBlobCount(t, env.arc, 3)
	return env, u, port
}

func TestSyncBeforeOnlyOldMail(t *testing.T) {
	quietLog()
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMailAt(t, u, "INBOX", "From: old@x.de\r\nSubject: old\r\n\r\nold body\r\n", time.Date(2020, 6, 1, 12, 0, 0, 0, time.Local))
	seedMail(t, u, "INBOX", "From: fresh@x.de\r\nSubject: fresh\r\n\r\nfresh body\r\n")
	env := syncTestEnv(t, port, "test", nil)

	var code int
	captureStdout(t, func() {
		code = run([]string{"sync", "-config", env.cfgPath, "-before", "2025-01-01"})
	})
	if code != 0 {
		t.Fatalf("sync -before exit = %d", code)
	}
	blobs, err := env.arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 1 {
		t.Fatalf("sync -before archived %d blob(s), want exactly the 1 old message", len(blobs))
	}
	msg, err := env.arc.get(blobs[0].name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(msg, []byte("Subject: old")) {
		t.Fatalf("wrong message archived: %q", msg)
	}
	// a later full sync picks up the rest — the state diff works unchanged
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("full sync exit = %d", code)
	}
	assertBlobCount(t, env.arc, 2)
}

func TestSyncBeforeBadDateRejected(t *testing.T) {
	quietLog()
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: a@x.de\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)
	var code int
	var stderr string
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"sync", "-config", env.cfgPath, "-before", "01.01.2025"})
		})
	})
	if !strings.Contains(stderr, "want YYYY-MM-DD") {
		t.Fatalf("bad-date rejection must name the expected format, got stderr: %q", stderr)
	}
	if code == 0 {
		t.Fatal("sync -before 01.01.2025 must be rejected (want YYYY-MM-DD)")
	}
	assertBlobCount(t, env.arc, 0)
}

func TestExpireRequiresBefore(t *testing.T) {
	quietLog()
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMail(t, u, "INBOX", "From: a@x.de\r\n\r\nbody\r\n")
	env := syncTestEnv(t, port, "test", nil)
	var code int
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", env.cfgPath})
	})
	if code == 0 {
		t.Fatal("expire without -before must refuse to run")
	}
	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("server lost mail without -before: %d left", got)
	}

	// malformed cutoff date
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", env.cfgPath, "-before", "01.01.2025"})
	})
	if code == 0 {
		t.Fatal("expire with malformed -before date must be rejected")
	}
	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("rejected-date run deleted mail: %d left", got)
	}
}

func TestExpireDryRunDoesNotDelete(t *testing.T) {
	env, u, _ := expireFixture(t)
	var stdout string
	var code int
	stdout = captureStdout(t, func() {
		code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01"})
	})
	if !strings.Contains(stdout, "dry run: test/INBOX: would delete 2 of 2 in-scope message(s)") {
		t.Fatalf("dry run stdout contract broken, got: %q", stdout)
	}
	if code != 0 {
		t.Fatalf("expire dry run exit = %d", code)
	}
	if got := serverMessages(t, u, "INBOX"); got != 3 {
		t.Fatalf("dry run deleted mail: %d left, want 3", got)
	}
	assertBlobCount(t, env.arc, 3)
	// state untouched — the dry run must not write deletions back
	st := env.state(t)
	if got := len(st.Accounts["test"]["INBOX"].UIDs); got != 3 {
		t.Fatalf("dry run modified state: %d UID(s), want 3", got)
	}
}

func TestExpireDeletesProvenOldMail(t *testing.T) {
	env, u, _ := expireFixture(t)
	// explicit -account filter: same result, exercises the filtered config
	if code := runExpire(t, env.cfgPath, "-account", "test", "-before", "2025-01-01"); code != 0 {
		t.Fatalf("expire dry run with -account exit = %d", code)
	}
	if got := serverMessages(t, u, "INBOX"); got != 3 {
		t.Fatalf("dry run deleted mail: %d left, want 3", got)
	}
	if code := runExpire(t, env.cfgPath, "-before", "2025-01-01", "-do"); code != 0 {
		t.Fatalf("expire -do exit = %d", code)
	}
	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("server has %d message(s) after expire, want 1 (the fresh one)", got)
	}
	// the archive keeps everything — append-only, freeing is server-side only
	assertBlobCount(t, env.arc, 3)
	// state drops the expunged UIDs
	st := env.state(t)
	if got := len(st.Accounts["test"]["INBOX"].UIDs); got != 1 {
		t.Fatalf("state keeps %d UID(s) after expire, want 1", got)
	}
	// a follow-up sync finds nothing new and is happy
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("post-expire sync exit = %d", code)
	}
	assertBlobCount(t, env.arc, 3)
}

func TestExpireSkipsUnprovenUID(t *testing.T) {
	env, u, _ := expireFixture(t)
	// sabotage: one old message's blob vanishes from the archive — expire
	// must not delete what it cannot prove we hold
	blobs, err := env.arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	var removed bool
	for _, b := range blobs {
		data, err := env.arc.get(b.name)
		if err == nil && bytes.Contains(data, []byte("Subject: old one")) {
			if err := os.Remove(filepath.Join(env.arc.dir, b.name)); err != nil {
				t.Fatal(err)
			}
			removed = true
			break
		}
	}
	if !removed {
		t.Fatal("could not find blob to sabotage")
	}
	if code := runExpire(t, env.cfgPath, "-before", "2025-01-01", "-do"); code != 0 {
		t.Fatalf("expire -do exit = %d", code)
	}
	if got := serverMessages(t, u, "INBOX"); got != 2 {
		t.Fatalf("server has %d message(s), want 2 (fresh + unproven old)", got)
	}
	st := env.state(t)
	if got := len(st.Accounts["test"]["INBOX"].UIDs); got != 2 {
		t.Fatalf("state keeps %d UID(s), want 2 (proven dropped, unproven kept)", got)
	}
}

func TestExpireSkipsNeverSyncedFolder(t *testing.T) {
	quietLog()
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMailAt(t, u, "INBOX", "From: old@x.de\r\nSubject: old\r\n\r\nbody\r\n", time.Date(2020, 1, 1, 0, 0, 0, 0, time.Local))
	env := syncTestEnv(t, port, "test", nil)
	// no sync ran — state has no folder entry
	if code := runExpire(t, env.cfgPath, "-before", "2025-01-01", "-do"); code != 0 {
		t.Fatalf("expire -do exit = %d", code)
	}
	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("expire deleted mail from a never-synced folder: %d left", got)
	}
}

// expire must refuse a broken/missing config (same shared loader as sync).
func TestExpireBadConfigRejected(t *testing.T) {
	quietLog()
	var code int
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", "/nonexistent/config.toml", "-before", "2025-01-01"})
	})
	if code == 0 {
		t.Fatal("expire with missing config must fail")
	}
}

// A configured folder that is not selectable on the server must fail the
// expire run (same misconfiguration rule as sync), not be silently skipped.
func TestExpireMissingConfiguredFolderRejected(t *testing.T) {
	quietLog()
	env, u, _ := expireFixture(t)
	cfg := env.cfg(t)
	cfg.Accounts[0].Folders = []string{"INBOX", "Ghost"}
	p := filepath.Join(env.dir, "ghost.toml")
	writeTestConfig(t, p, cfg)
	var stderr string
	var code int
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"expire", "-config", p, "-before", "2025-01-01"})
		})
	})
	if code == 0 {
		t.Fatal("expire with a configured-but-missing folder must exit non-zero")
	}
	if !strings.Contains(stderr, `configured folder "Ghost" not found`) {
		t.Fatalf("stderr must name the missing folder, got: %q", stderr)
	}
	if got := serverMessages(t, u, "INBOX"); got != 3 {
		t.Fatalf("misconfigured run deleted mail: %d left", got)
	}
}

func TestExpireCorruptStateRejected(t *testing.T) {
	quietLog()
	env, u, _ := expireFixture(t)
	stPath := env.cfg(t).StateFile
	if err := os.WriteFile(stPath, []byte("this is [not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01", "-do"})
	})
	if code == 0 {
		t.Fatal("expire with corrupt state file must exit non-zero")
	}
	if got := serverMessages(t, u, "INBOX"); got != 3 {
		t.Fatalf("expire without usable state deleted mail: %d left", got)
	}
}

func TestExpireZeroAccountsRejected(t *testing.T) {
	quietLog()
	env := newTestEnv(t) // valid config, no accounts
	var code int
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01"})
	})
	if code == 0 {
		t.Fatal("expire with zero accounts must fail")
	}
}

// -account filtering and account-level failures: dial/login/selectFolders
// errors are collected per account and must fail the run.
func TestExpireAccountFilterAndFaults(t *testing.T) {
	quietLog()
	env, u, port := expireFixture(t)

	// unknown -account: refused
	var code int
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", env.cfgPath, "-account", "nosuch", "-before", "2025-01-01"})
	})
	if code == 0 {
		t.Fatal("expire -account nosuch must fail")
	}
	if got := serverMessages(t, u, "INBOX"); got != 3 {
		t.Fatalf("failed filter run deleted mail: %d left", got)
	}

	// a second account with a dead server: expire must fail the run but the
	// healthy account still expires
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	port2 := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // leave the port free-ish; the dial failure is what we want anyway
	cfgPath2 := filepath.Join(t.TempDir(), "cfg.toml")
	keyPath := filepath.Join(filepath.Dir(env.cfgPath), "key.txt")
	os.WriteFile(cfgPath2, []byte(fmt.Sprintf(
		"state_file = %q\narchive_dir = %q\nkey_file = %q\n\n[[accounts]]\nname = \"bad\"\nhost = \"127.0.0.1\"\nport = %d\nsecurity = \"none\"\nuser = \"x\"\npassword = \"x\"\n\n[[accounts]]\nname = \"test\"\nhost = \"127.0.0.1\"\nport = %d\nsecurity = \"none\"\nuser = \"testuser\"\npassword = \"testpw\"\n",
		filepath.Join(filepath.Dir(env.cfgPath), "state.json"), env.arc.dir, keyPath, port2, port)), 0o600)
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", cfgPath2, "-before", "2025-01-01", "-do"})
	})
	if code == 0 {
		t.Fatal("expire with one failing account must exit non-zero")
	}
	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("healthy account did not expire alongside the failing one: %d left, want 1", got)
	}
}

// UIDVALIDITY guard: after the folder is recreated with a fresh UIDVALIDITY,
// expire must refuse to touch it — the remembered UIDs could now point at
// different messages.
func TestExpireSkipsUIDValidityChanged(t *testing.T) {
	quietLog()
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMailAt(t, u, "INBOX", "From: old@x.de\r\nSubject: old\r\n\r\nbody\r\n", time.Date(2020, 1, 1, 0, 0, 0, 0, time.Local))
	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit = %d", code)
	}
	// recreate INBOX and re-seed the IDENTICAL message: new UIDVALIDITY, same
	// bytes, UID 1 again — so the hash proof would pass and only the
	// UIDVALIDITY guard can prevent deletion (mutation-tested)
	if err := u.Delete("INBOX"); err != nil {
		t.Fatal(err)
	}
	if err := u.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	seedMailAt(t, u, "INBOX", "From: old@x.de\r\nSubject: old\r\n\r\nbody\r\n", time.Date(2020, 1, 1, 0, 0, 0, 0, time.Local))
	var stderr string
	var code int
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01", "-do"})
		})
	})
	if code != 0 {
		t.Fatalf("expire -do exit = %d", code)
	}
	if !strings.Contains(stderr, "UIDVALIDITY changed") {
		t.Fatalf("must refuse with a UIDVALIDITY warning, got: %q", stderr)
	}
	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("expire deleted mail after UIDVALIDITY change: %d left, want 1", got)
	}
}

func TestExpireNothingToDo(t *testing.T) {
	env, u, _ := expireFixture(t)
	if code := runExpire(t, env.cfgPath, "-before", "1990-01-01", "-do"); code != 0 {
		t.Fatalf("expire -do exit = %d", code)
	}
	if got := serverMessages(t, u, "INBOX"); got != 3 {
		t.Fatalf("nothing-to-do run deleted mail: %d left", got)
	}
}

// Proof-loop skip paths via a fetch hook: the server's SEARCH answers from
// real INTERNALDATEs, but the fetch handler misbehaves — the first response
// lacks INTERNALDATE entirely, the second claims a date after the cutoff.
// Both bodies are genuine archive content, so ONLY the guards can explain a
// skip; expire must delete nothing.
func TestExpireSkipsIncompleteAndDriftedFetch(t *testing.T) {
	quietLog()
	old1 := "From: a@x.de\r\nSubject: incomplete\r\n\r\nbody a\r\n"
	old2 := "From: b@x.de\r\nSubject: drifted\r\n\r\nbody b\r\n"
	u, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, fetch: func(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
			seqs := []uint32{1, 2}
			uids := []imap.UID{1, 2}
			// response 1: body, no INTERNALDATE
			rw1 := w.CreateMessage(seqs[0])
			rw1.WriteUID(uids[0])
			wc := rw1.WriteBodySection(&imap.FetchItemBodySection{Peek: true}, int64(len(old1)))
			wc.Write([]byte(old1)) //nolint:errcheck
			wc.Close()             //nolint:errcheck
			if err := rw1.Close(); err != nil {
				return err
			}
			// response 2: genuine body but INTERNALDATE after the cutoff
			rw2 := w.CreateMessage(seqs[1])
			rw2.WriteUID(uids[1])
			rw2.WriteInternalDate(time.Now()) // the search said "before 2025"
			wc = rw2.WriteBodySection(&imap.FetchItemBodySection{Peek: true}, int64(len(old2)))
			wc.Write([]byte(old2)) //nolint:errcheck
			wc.Close()             //nolint:errcheck
			return rw2.Close()
		}}
	})
	seedMailAt(t, u, "INBOX", old1, time.Date(2020, 1, 1, 0, 0, 0, 0, time.Local))
	seedMailAt(t, u, "INBOX", old2, time.Date(2021, 1, 1, 0, 0, 0, 0, time.Local))
	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit = %d", code)
	}
	assertBlobCount(t, env.arc, 2)

	if code := runExpire(t, env.cfgPath, "-before", "2025-01-01", "-do"); code != 0 {
		t.Fatalf("expire -do exit = %d", code)
	}
	if got := serverMessages(t, u, "INBOX"); got != 2 {
		t.Fatalf("unproven messages were deleted: %d left, want 2", got)
	}
	st := env.state(t)
	if got := len(st.Accounts["test"]["INBOX"].UIDs); got != 2 {
		t.Fatalf("state lost UIDs on a nothing-deleted expire: %d", got)
	}
}

// A blob that exists but no longer decrypts (bit rot, provider mangling) must
// block deletion of its message.
func TestExpireSkipsCorruptBlob(t *testing.T) {
	env, u, _ := expireFixture(t)
	blobs, err := env.arc.blobs()
	if err != nil {
		t.Fatal(err)
	}
	var corrupted bool
	for _, b := range blobs {
		data, err := env.arc.get(b.name)
		if err == nil && bytes.Contains(data, []byte("Subject: old one")) {
			p := filepath.Join(env.arc.dir, b.name)
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			raw[10] ^= 0xFF // flip one payload byte — age AEAD must reject it
			if err := os.WriteFile(p, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			corrupted = true
			break
		}
	}
	if !corrupted {
		t.Fatal("could not corrupt a blob for the test")
	}
	if code := runExpire(t, env.cfgPath, "-before", "2025-01-01", "-do"); code != 0 {
		t.Fatalf("expire -do exit = %d", code)
	}
	if got := serverMessages(t, u, "INBOX"); got != 2 {
		t.Fatalf("server has %d message(s), want 2 (fresh + corrupt-blob old)", got)
	}
}

// writeTestConfig serializes cfg as TOML (for mutating a fixture's config).
func writeTestConfig(t *testing.T, path string, cfg *Config) {
	t.Helper()
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Server command faults during expire (hooked at the session boundary, one
// toggle per run): every faulted run must exit non-zero and delete nothing —
// including a STORE that flags \Deleted but is followed by a failing
// UID EXPUNGE (the messages stay until the expunge actually happened).
func TestExpireServerCommandFaults(t *testing.T) {
	quietLog()
	var listErr, selectErr, fetchErr, storeErr, expungeErr atomic.Bool
	u, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{
			Session: s,
			list: func(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
				if listErr.Load() {
					return errors.New("list fault")
				}
				return s.List(w, ref, patterns, options)
			},
			selectM: func(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
				if selectErr.Load() {
					return nil, errors.New("select fault")
				}
				return s.Select(mailbox, options)
			},
			fetch: func(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
				if fetchErr.Load() {
					// session returns an error -> server replies tagged NO ->
					// the client's FetchCommand surfaces it via Close()
					return errors.New("fetch fault")
				}
				return s.Fetch(w, numSet, options)
			},
			store: func(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
				if storeErr.Load() {
					return errors.New("store fault")
				}
				return s.Store(w, numSet, flags, options)
			},
			expunge: func(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
				if expungeErr.Load() {
					return errors.New("expunge fault")
				}
				return s.Expunge(w, uids)
			},
		}
	})
	seedMailAt(t, u, "INBOX", "From: a@x.de\r\nSubject: old a\r\n\r\nbody a\r\n", time.Date(2020, 1, 1, 0, 0, 0, 0, time.Local))
	seedMailAt(t, u, "INBOX", "From: b@x.de\r\nSubject: old b\r\n\r\nbody b\r\n", time.Date(2021, 1, 1, 0, 0, 0, 0, time.Local))
	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit = %d", code)
	}

	type toggle struct {
		name string
		set  func(bool)
	}
	// (SEARCH faults are not injectable this way: Session.Search's NumKind
	// parameter is an internal imapwire type, unnameable from tests — the
	// fault branch is the same trivial error propagation as select's)
	toggles := []toggle{
		{"list", listErr.Store}, {"select", selectErr.Store},
		{"fetch (proof command tagged NO)", fetchErr.Store},
		{"store", storeErr.Store}, {"expunge", expungeErr.Store},
	}
	for _, tg := range toggles {
		tg.set(true)
		var code int
		captureStdout(t, func() {
			code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01", "-do"})
		})
		tg.set(false)
		if code == 0 {
			t.Fatalf("expire with %s fault must exit non-zero", tg.name)
		}
		if got := serverMessages(t, u, "INBOX"); got != 2 {
			t.Fatalf("%s fault deleted mail: %d left", tg.name, got)
		}
		st := env.state(t)
		if got := len(st.Accounts["test"]["INBOX"].UIDs); got != 2 {
			t.Fatalf("%s fault corrupted state: %d UID(s)", tg.name, got)
		}
	}

	// all faults cleared: the same invocation now succeeds fully
	if code := runExpire(t, env.cfgPath, "-before", "2025-01-01", "-do"); code != 0 {
		t.Fatalf("clean expire exit = %d", code)
	}
	if got := serverMessages(t, u, "INBOX"); got != 0 {
		t.Fatalf("server has %d message(s) after clean expire, want 0", got)
	}
}

// Auth failures must be reported per account and delete nothing.
func TestExpireAuthFaults(t *testing.T) {
	quietLog()
	u, port := startMemIMAP(t, "testuser", "testpw")
	seedMailAt(t, u, "INBOX", "From: a@x.de\r\nSubject: old\r\n\r\nbody\r\n", time.Date(2020, 1, 1, 0, 0, 0, 0, time.Local))
	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit = %d", code)
	}
	cfg := env.cfg(t)

	// wrong password (login NO)
	wrong := *cfg
	wrong.Accounts[0].Password = "totally-wrong"
	wrongPath := filepath.Join(env.dir, "wrong.toml")
	writeTestConfig(t, wrongPath, &wrong)
	var code int
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", wrongPath, "-before", "2025-01-01", "-do"})
	})
	if code == 0 {
		t.Fatal("expire with wrong password must exit non-zero")
	}

	// password_cmd that fails
	badCmd := *cfg
	badCmd.Accounts[0].Password = ""
	badCmd.Accounts[0].PasswordCmd = "exit 1"
	cmdPath := filepath.Join(env.dir, "badcmd.toml")
	writeTestConfig(t, cmdPath, &badCmd)
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", cmdPath, "-before", "2025-01-01", "-do"})
	})
	if code == 0 {
		t.Fatal("expire with failing password_cmd must exit non-zero")
	}

	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("auth-faulted expire deleted mail: %d left", got)
	}
}

// When the state file cannot be written after successful deletions, the run
// must say so (exit non-zero) — not pretend everything was fine. The
// deletions themselves stand; the next sync will simply re-see nothing.
func TestExpireStateSaveFault(t *testing.T) {
	quietLog()
	env, u, _ := expireFixture(t)
	st := env.cfg(t).StateFile
	// save() writes state.json.tmp + renames, so the state file's own mode
	// cannot fault it — block the tmp path instead (WriteFile → EISDIR)
	if err := os.Mkdir(st+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	var code int
	captureStdout(t, func() {
		code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01", "-do"})
	})
	if code == 0 {
		t.Fatal("expire with failing state save must exit non-zero")
	}
	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("server has %d message(s), want 1 (deletions stand despite save failure)", got)
	}
}

// deleteServerSide mimics another client expunging mail: it opens its own
// IMAP session and UID-expunges the given UIDs.
func deleteServerSide(t *testing.T, port int, user, pass, mailbox string, uids ...imap.UID) {
	t.Helper()
	c, err := imapclient.DialInsecure(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck — test helper
	if err := c.Login(user, pass).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Select(mailbox, nil).Wait(); err != nil {
		t.Fatal(err)
	}
	set := imap.UIDSetNum(uids...)
	if err := c.Store(set, &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.UIDExpunge(set).Close(); err != nil {
		t.Fatal(err)
	}
}

// Full sync must prune remembered UIDs of messages that vanished from the
// server (other-client expunge, or a crash between expire's UID EXPUNGE and
// the state save) — otherwise expire re-considers ghosts forever. A -before
// sync must NOT prune: its present set is partial, so "not present" there
// just means "after the cutoff".
func TestSyncPrunesVanishedUIDsFromState(t *testing.T) {
	quietLog()
	env, u, port := expireFixture(t) // 3 messages, all synced
	st := env.state(t)
	if got := len(st.Accounts["test"]["INBOX"].UIDs); got != 3 {
		t.Fatalf("fixture synced %d UID(s), want 3", got)
	}

	// another client deletes the two old messages server-side
	deleteServerSide(t, port, "testuser", "testpw", "INBOX", 1, 2)
	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("server-side delete failed: %d left, want 1", got)
	}

	// -before sync: nothing before the cutoff remains; state must be intact
	var code int
	captureStdout(t, func() {
		code = run([]string{"sync", "-config", env.cfgPath, "-before", "2025-01-01"})
	})
	if code != 0 {
		t.Fatalf("sync -before exit = %d", code)
	}
	st = env.state(t)
	if got := len(st.Accounts["test"]["INBOX"].UIDs); got != 3 {
		t.Fatalf("-before sync pruned state: %d UID(s), want 3", got)
	}

	// full sync: the vanished UIDs are provably gone -> pruned
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit = %d", code)
	}
	st = env.state(t)
	if got := len(st.Accounts["test"]["INBOX"].UIDs); got != 1 {
		t.Fatalf("full sync did not prune vanished UIDs: %d UID(s), want 1", got)
	}
	// the archived blobs are untouched (append-only)
	assertBlobCount(t, env.arc, 3)
}

// rawReply is a scripted wire reply: exactly the bytes to write, and whether
// to drop the connection right after (needed for truncated literals — the
// client's literal reader blocks until the promised size or the socket dies).
type rawReply struct {
	raw  string
	drop bool
}

// startRawScriptIMAP serves just enough scripted IMAP to reach a UID SEARCH:
// greeting, LOGIN, LIST, SELECT/EXAMINE are answered correctly; `search`
// decides the UID SEARCH reply, `fetch` (when non-nil) the FETCH reply.
// Anything else gets a plain tagged OK. This is the injection point for
// server-side SEARCH faults, which the in-memory session hook cannot express.
func startRawScriptIMAP(t *testing.T, search func(tag string) rawReply, fetch func(tag string) rawReply) int {
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
			go serveRawScriptIMAP(c, search, fetch)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// seedRawState writes an expire-ready state matching the raw script server
// (UIDVALIDITY 42): both UIDs are remembered as archived.
func seedRawState(t *testing.T, env *testEnv) {
	t.Helper()
	st := `{"accounts":{"test":{"INBOX":{"uidvalidity":42,"uids":[1,2]}}}}`
	if err := os.WriteFile(env.cfg(t).StateFile, []byte(st), 0o600); err != nil {
		t.Fatal(err)
	}
}

func serveRawScriptIMAP(c net.Conn, search, fetch func(tag string) rawReply) {
	defer c.Close() //nolint:errcheck
	rd := bufio.NewReader(c)
	c.Write([]byte("* OK ready\r\n")) //nolint:errcheck
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasSuffix(line, "+") { // literal continuation (LOGIN args) — accept
			continue
		}
		sp := strings.IndexByte(line, ' ')
		if sp <= 0 {
			continue
		}
		tag, rest := line[:sp], line[sp+1:]
		var out string
		var drop bool
		switch {
		case strings.HasPrefix(rest, "LOGIN"), strings.HasPrefix(rest, "LIST"), strings.HasPrefix(rest, "CAPABILITY"):
			if strings.HasPrefix(rest, "LIST") {
				out = "* LIST () \"/\" \"INBOX\"\r\n"
			}
			out += tag + " OK done\r\n"
		case strings.HasPrefix(rest, "SELECT"), strings.HasPrefix(rest, "EXAMINE"):
			out = "* 3 EXISTS\r\n* OK [UIDVALIDITY 42] uids\r\n* OK [UIDNEXT 4] next\r\n" + tag + " OK selected\r\n"
		case strings.Contains(rest, "SEARCH"):
			r := search(tag)
			out, drop = r.raw, r.drop
		case strings.Contains(rest, "FETCH"):
			if fetch != nil {
				r := fetch(tag)
				out, drop = r.raw, r.drop
			} else {
				out = "* 1 FETCH (UID 1)\r\n" + tag + " OK done\r\n"
			}
		default:
			out = tag + " OK done\r\n"
		}
		c.Write([]byte(out)) //nolint:errcheck
		if drop {
			return // scripted connection drop
		}
	}
}

// A tagged NO on the date-scoped SEARCH must fail the sync (the -before
// present set is unknown — proceeding would silently mis-archive).
func TestSyncBeforeSearchTaggedNO(t *testing.T) {
	quietLog()
	port := startRawScriptIMAP(t,
		func(tag string) rawReply { return rawReply{tag + " NO search refused\r\n", false} },
		nil)
	env := syncTestEnv(t, port, "test", []string{"INBOX"})
	var stderr string
	var code int
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"sync", "-config", env.cfgPath, "-before", "2025-01-01"})
		})
	})
	if code == 0 {
		t.Fatal("tagged NO on SEARCH was silently swallowed")
	}
	if !strings.Contains(stderr, "search before 2025-01-01") {
		t.Fatalf("error must name the failed search, got: %q", stderr)
	}
	if blobs, _ := env.arc.blobs(); len(blobs) != 0 {
		t.Fatalf("failed search archived data: %d blob(s)", len(blobs))
	}
}

// Same fault in expire: an unknown present set must abort the run before any
// proof — and nothing may be touched.
func TestExpireSearchTaggedNO(t *testing.T) {
	quietLog()
	port := startRawScriptIMAP(t,
		func(tag string) rawReply { return rawReply{tag + " NO search refused\r\n", false} },
		nil)
	env := syncTestEnv(t, port, "test", []string{"INBOX"})
	seedRawState(t, env) // raw server's SELECT reports UIDVALIDITY 42
	var stderr string
	var code int
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01"})
		})
	})
	if code == 0 {
		t.Fatal("tagged NO on expire's SEARCH was silently swallowed")
	}
	if !strings.Contains(stderr, "folder INBOX: search: imap: NO search refused") {
		t.Fatalf("error must name folder and search, got: %q", stderr)
	}
}

// The proof FETCH promising one literal size but delivering less must abort
// the expire run — the truncation guard refuses to reason about a body it
// did not fully receive. (Connection-drop during a literal is beta.9's
// EOF-means-done short read, caught by the Size() check.)
func TestExpireProofFetchTruncated(t *testing.T) {
	quietLog()
	if raceEnabled {
		t.Skip("go-imap v2 beta.9 client races on EOF-during-literal — upstream bug, not ours")
	}
	port := startRawScriptIMAP(t,
		func(tag string) rawReply { return rawReply{"* SEARCH 1\r\n" + tag + " OK done\r\n", false} },
		func(tag string) rawReply {
			// promise 100 bytes of body, deliver 7, drop the socket — without
			// the drop the client's literal reader blocks until respReadTimeout
			return rawReply{`* 1 FETCH (UID 1 INTERNALDATE "01-Jan-2020 06:00:00 +0000" BODY[] {100}` + "\r\ntruncat", true}
		})
	env := syncTestEnv(t, port, "test", []string{"INBOX"})
	seedRawState(t, env)
	var stderr string
	var code int
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01"})
		})
	})
	if code == 0 {
		t.Fatal("truncated proof body was silently swallowed")
	}
	if !strings.Contains(stderr, "body truncated: got 7 of 100 bytes") {
		t.Fatalf("error must report the truncation, got: %q", stderr)
	}
}

// A broken archive (the archive path is not even a directory — e.g. the
// synced folder was wrecked) must block every deletion: os.Stat fails with
// ENOTDIR, archiveHolds reports failure, every candidate is skipped.
func TestExpireBrokenArchiveSkipsEverything(t *testing.T) {
	quietLog()
	env, u, _ := expireFixture(t)
	archiveDir := env.arc.dir
	stPath := env.cfg(t).StateFile
	_ = stPath
	if err := os.RemoveAll(archiveDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archiveDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr string
	var code int
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01", "-do"})
		})
	})
	if code != 0 {
		t.Fatalf("expire with a broken archive must still exit 0 (skips are warnings), got %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "archive check failed") {
		t.Fatalf("every candidate must be skipped with a warning, got: %q", stderr)
	}
	if got := serverMessages(t, u, "INBOX"); got != 3 {
		t.Fatalf("broken archive deleted mail: %d left, want 3", got)
	}
}

// The drift guard's boundary is pinned here, not just its direction: a
// message whose FETCHED INTERNALDATE is exactly cutoff+1h must be skipped
// (the guard demands strictly-before), even though the server's date-only
// SEARCH still reports it in the BEFORE set. The drifted date is computed
// from the parsed cutoff, so this holds in every timezone. (Mutation check:
// widening the guard to cutoff+1d must fail this test.)
func TestExpireCutoffBoundaryExclusive(t *testing.T) {
	quietLog()
	msg := "From: a@x.de\r\nSubject: boundary\r\n\r\nbody\r\n"
	u, port := startMemIMAPHook(t, "testuser", "testpw", func(s imapserver.Session) imapserver.Session {
		return &hookSession{Session: s, fetch: func(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
			// serve a stored-old message with a FETCHED INTERNALDATE one hour
			// after the local-midnight cutoff: server search says "in scope",
			// the message itself disagrees — the guard must trust the message
			rw := w.CreateMessage(1)
			rw.WriteUID(1)
			rw.WriteInternalDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.Local))
			wc := rw.WriteBodySection(&imap.FetchItemBodySection{Peek: true}, int64(len(msg)))
			wc.Write([]byte(msg)) //nolint:errcheck
			wc.Close()            //nolint:errcheck
			return rw.Close()
		}}
	})
	seedMailAt(t, u, "INBOX", msg, time.Date(2020, 1, 1, 0, 0, 0, 0, time.Local)) // stored: safely before
	env := syncTestEnv(t, port, "test", nil)
	if code := runSync(t, env.cfgPath); code != 0 {
		t.Fatalf("sync exit = %d", code)
	}
	var stderr string
	var code int
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"expire", "-config", env.cfgPath, "-before", "2025-01-01", "-do"})
		})
	})
	if code != 0 {
		t.Fatalf("expire -do exit = %d", code)
	}
	if !strings.Contains(stderr, "INTERNALDATE outside requested window") {
		t.Fatalf("boundary message must be skipped with a drift warning, got: %q", stderr)
	}
	if got := serverMessages(t, u, "INBOX"); got != 1 {
		t.Fatalf("cutoff-boundary message was deleted: %d left, want 1", got)
	}
}

// Missing -before must refuse loudly (mutation check: dropping the
// requirement must fail this test — without it expire would need no explicit
// cutoff at all).
func TestExpireMissingBeforeRejected(t *testing.T) {
	quietLog()
	env, _, _ := expireFixture(t)
	var stderr string
	var code int
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"expire", "-config", env.cfgPath})
		})
	})
	if code == 0 {
		t.Fatal("expire without -before must exit non-zero")
	}
	if !strings.Contains(stderr, "requires -before") {
		t.Fatalf("must name the missing requirement, got: %q", stderr)
	}
}
