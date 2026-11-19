package main

// Unit tests for the sync plumbing that doesn't need a live IMAP server.

import (
	"strings"
	"testing"
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
			name:    "trailing newline trimmed",
			acc:     Account{Name: "a", PasswordCmd: "printf 'pw\\n\\r\\n'"},
			want:    "pw",
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
