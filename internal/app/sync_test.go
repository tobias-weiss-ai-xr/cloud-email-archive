package app

// Unit tests for the sync plumbing that doesn't need a live IMAP server.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

func TestAccountPassword(t *testing.T) {
	tests := []struct {
		name    string
		acc     Account
		want    string
		wantErr string // "" = no error
	}{
		{
			name: "plaintext password",
			acc:  Account{Name: "a", Password: "s3cret"},
			want: "s3cret",
		},
		{
			name: "password_cmd",
			acc:  Account{Name: "a", PasswordCmd: "echo cmdpw"},
			want: "cmdpw",
		},
		{
			name: "password wins over password_cmd",
			acc:  Account{Name: "a", Password: "direct", PasswordCmd: "echo other"},
			want: "direct",
		},
		{
			name: "trailing newline trimmed",
			acc:  Account{Name: "a", PasswordCmd: "printf 'pw\\n\\r\\n'"},
			want: "pw",
		},
		{
			name:    "neither set",
			acc:     Account{Name: "uni_mail"},
			wantErr: "uni_mail",
		},
		{
			name:    "failing command",
			acc:     Account{Name: "a", PasswordCmd: "exit 3"},
			wantErr: "password_cmd failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := accountPassword(&tt.acc)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error containing %q, got %v (pw=%q)", tt.wantErr, err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("password = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBytesCount(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1 << 20, "1.0 MiB"},
		{1 << 30, "1.0 GiB"},
		{3 << 30, "3.0 GiB"},
	}
	for _, tt := range tests {
		if got := bytesCount(tt.n); got != tt.want {
			t.Errorf("bytesCount(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestDialRefused(t *testing.T) {
	// nothing listens on port 1 → dial must surface a connection error
	acc := &Account{Name: "a", Host: "127.0.0.1", Port: 1, Security: "none"}
	if _, err := dial(acc); err == nil {
		t.Fatal("dial to closed port must fail")
	}
	// invalid security value falls through to implicit TLS dial, which also
	// fails on a closed port — same expectations
	acc.Security = "bogus"
	if _, err := dial(acc); err == nil {
		t.Fatal("dial with unknown security on closed port must fail")
	}
}

func TestWantAccount(t *testing.T) {
	if !wantAccount("", "anything") {
		t.Error("empty filter = all accounts")
	}
	if !wantAccount("Faculty", "faculty") || !wantAccount("FACULTY", "faculty") {
		t.Error("wantAccount must be case-insensitive")
	}
	if wantAccount("faculty", "verwaltung") {
		t.Error("different account must not match")
	}
}

// dial() must perform a real STARTTLS upgrade against a server advertising it.
// Self-signed cert with an IP SAN matching the dial target — real handshake,
// real verification, no insecure shortcuts on the client side.
func TestDialStartTLS(t *testing.T) {
	skipOnWindows(t, "Windows system cert store ignores SSL_CERT_FILE")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	// the client verifies against the system pool — trust our test CA the
	// same way a real deployment does (SSL_CERT_FILE), no InsecureSkipVerify
	pemPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(pemPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", pemPath)
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	mem := imapmemserver.New()
	u := imapmemserver.NewUser("testuser", "testpw")
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
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		ln.Close()
	})
	go server.Serve(ln)
	port := ln.Addr().(*net.TCPAddr).Port

	a := &Account{Name: "t", Host: "127.0.0.1", Port: port, Security: "starttls", User: "testuser", Password: "testpw"}
	c, err := dial(a)
	if err != nil {
		t.Fatalf("starttls dial failed: %v", err)
	}
	defer c.Close()
	if err := c.Login(a.User, a.Password).Wait(); err != nil {
		t.Fatalf("login over starttls failed: %v", err)
	}
}

// selectFolders semantics against a live server: empty list = all, "*" = all,
// case-insensitive matching, missing folders reported as missing.
func TestSelectFoldersSemantics(t *testing.T) {
	u, port := startMemIMAP(t, "testuser", "testpw")
	if err := u.Create("Archiv", nil); err != nil {
		t.Fatal(err)
	}
	// security=none: the memserver is plaintext (also covers dial's none branch)
	c, err := dial(&Account{Name: "t", Host: "127.0.0.1", Port: port, Security: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("testuser", "testpw").Wait(); err != nil {
		t.Fatal(err)
	}
	a := Account{Name: "t"}

	t.Run("empty list = all folders", func(t *testing.T) {
		a.Folders = nil
		found, missing, err := selectFolders(c, &a, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != 0 || len(found) < 2 {
			t.Fatalf("found=%v missing=%v, want both folders, none missing", found, missing)
		}
	})
	t.Run("star = all folders", func(t *testing.T) {
		a.Folders = []string{"*"}
		found, missing, err := selectFolders(c, &a, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != 0 || len(found) < 2 {
			t.Fatalf("found=%v missing=%v", found, missing)
		}
	})
	t.Run("case-insensitive match, missing reported", func(t *testing.T) {
		a.Folders = []string{"inbox", "Ghost"}
		found, missing, err := selectFolders(c, &a, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || !strings.EqualFold(found[0], "inbox") {
			t.Fatalf("found=%v, want inbox", found)
		}
		if len(missing) != 1 || missing[0] != "Ghost" {
			t.Fatalf("missing=%v, want Ghost", missing)
		}
	})
}

// syncAccount must fail before dialing when the account has no credentials.
func TestSyncAccountNoPassword(t *testing.T) {
	a := &Account{Name: "nopw", Host: "127.0.0.1", Port: 1, Security: "none"}
	_, err := syncAccount(&Config{ArchiveDir: t.TempDir()}, a, newArchive(t.TempDir(), testID(t)),
		&State{Accounts: map[string]map[string]*FolderState{}}, quietLog(), nil)
	if err == nil || !strings.Contains(err.Error(), "neither password nor password_cmd") {
		t.Fatalf("err = %v, want credential error", err)
	}
}
