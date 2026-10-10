package main

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	if err := run(context.Background(), path); err != nil {
		t.Fatalf("run: %v", err)
	}
	// Running again against the same database exercises migration of an
	// existing schema and replacing an existing user's password.
	if err := run(context.Background(), path); err != nil {
		t.Fatalf("second run: %v", err)
	}
}
