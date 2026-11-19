package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseDateArg(t *testing.T) {
	tests := []struct {
		in      string
		want    string // formatted expectation, empty = error expected
		wantErr string
	}{
		{in: "2025-01-01", want: "2025-01-01"},
		{in: " 2025-01-01 ", want: "2025-01-01"}, // tolerant of stray spaces
		{in: "2024-02-29", want: "2024-02-29"},   // leap day is valid
		{in: "", wantErr: "want YYYY-MM-DD"},
		{in: "   ", wantErr: "want YYYY-MM-DD"},
		{in: "01.01.2025", wantErr: "want YYYY-MM-DD"},
		{in: "2025-1-1", wantErr: "want YYYY-MM-DD"},
		{in: "2025-13-01", wantErr: "want YYYY-MM-DD"},
		{in: "2023-02-29", wantErr: "want YYYY-MM-DD"}, // not a leap year
	}
	for _, tt := range tests {
		got, err := parseDateArg(tt.in)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseDateArg(%q) error = %v, want %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDateArg(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got.Format("2006-01-02") != tt.want {
			t.Errorf("parseDateArg(%q) = %s, want %s", tt.in, got.Format("2006-01-02"), tt.want)
		}
		if h, m, s := got.Clock(); h != 0 || m != 0 || s != 0 {
			t.Errorf("parseDateArg(%q) must be midnight, got %02d:%02d:%02d", tt.in, h, m, s)
		}
	}
	// local time, not UTC — the date the operator types is local
	got, err := parseDateArg("2025-01-01")
	if err != nil {
		t.Fatal(err)
	}
	if got.Location() != time.Local {
		t.Errorf("parseDateArg must return local time, got %v", got.Location())
	}
}
