package passkeygorm

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/tpyle/auth/passkey"
	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
)

func TestMigrateIsIdempotent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("second Migrate: %v", err)
		}
		for _, m := range []any{&User{}, &Credential{}, &Ceremony{}} {
			if !db.Migrator().HasTable(m) {
				t.Errorf("table for %T missing", m)
			}
		}
	})
}

func TestEnsureUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		tests := []struct {
			name, subject, userName, displayName string
			wantName, wantDisplayName            string
		}{
			{"all names", "alice", "alice@example.com", "Alice A.", "alice@example.com", "Alice A."},
			{"no display name", "bob", "bob@example.com", "", "bob@example.com", ""},
			{"no names", "carol", "", "", "carol", ""},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				u, err := s.EnsureUser(ctx, tt.subject, tt.userName, tt.displayName)
				if err != nil {
					t.Fatalf("EnsureUser: %v", err)
				}
				if u.Subject != tt.subject || u.Name != tt.wantName || u.DisplayName != tt.wantDisplayName {
					t.Errorf("user = %+v, want subject %q, name %q, display name %q", u, tt.subject, tt.wantName, tt.wantDisplayName)
				}
				if len(u.Handle) != passkey.UserHandleLength {
					t.Errorf("handle length = %d, want %d", len(u.Handle), passkey.UserHandleLength)
				}

				// A second call returns the same user, ignoring new names.
				again, err := s.EnsureUser(ctx, tt.subject, "other", "Other")
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(again.Handle, u.Handle) || again.Name != u.Name || again.DisplayName != u.DisplayName {
					t.Errorf("second EnsureUser = %+v, want %+v", again, u)
				}
			})
		}
		if n := countRows(t, db, &User{}); n != int64(len(tests)) {
			t.Errorf("users = %d, want %d", n, len(tests))
		}
		if _, err := s.EnsureUser(ctx, "", "name", ""); err == nil {
			t.Error("EnsureUser accepted an empty subject")
		}
	})
}

func TestEnsureUserConcurrent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		const callers = 16
		handles := make([][]byte, callers)
		errs := make([]error, callers)
		var wg sync.WaitGroup
		for i := range callers {
			wg.Go(func() {
				u, err := s.EnsureUser(context.Background(), "alice", "alice", "")
				handles[i], errs[i] = u.Handle, err
			})
		}
		wg.Wait()
		for i := range callers {
			if errs[i] != nil {
				t.Fatalf("caller %d: %v", i, errs[i])
			}
			if !bytes.Equal(handles[i], handles[0]) {
				t.Fatalf("callers got different handles")
			}
		}
	})
}

func TestLookupUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		alice, err := s.EnsureUser(ctx, "alice", "alice@example.com", "Alice")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.EnsureUser(ctx, "bob", "", ""); err != nil {
			t.Fatal(err)
		}

		got, err := s.LookupUser(ctx, "alice")
		if err != nil {
			t.Fatalf("LookupUser: %v", err)
		}
		assertUser(t, got, alice)

		got, err = s.LookupUserByHandle(ctx, alice.Handle)
		if err != nil {
			t.Fatalf("LookupUserByHandle: %v", err)
		}
		assertUser(t, got, alice)

		for _, subject := range []string{"carol", "", "ALICE"} {
			if _, err := s.LookupUser(ctx, subject); !errors.Is(err, auth.ErrUserNotFound) {
				t.Errorf("LookupUser(%q) err = %v, want ErrUserNotFound", subject, err)
			}
		}
		prefix := alice.Handle[:len(alice.Handle)-1]
		for name, handle := range map[string][]byte{
			"unknown": passkey.NewUserHandle(),
			"empty":   nil,
			"prefix":  prefix,
			"longer":  append(bytes.Clone(alice.Handle), 0),
		} {
			if _, err := s.LookupUserByHandle(ctx, handle); !errors.Is(err, auth.ErrUserNotFound) {
				t.Errorf("LookupUserByHandle(%s) err = %v, want ErrUserNotFound", name, err)
			}
		}
	})
}

func TestDeleteUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		for _, subject := range []string{"alice", "bob"} {
			if _, err := s.EnsureUser(ctx, subject, "", ""); err != nil {
				t.Fatal(err)
			}
			mustCreateCredential(t, s, newCredential(subject))
		}
		if err := s.DeleteUser(ctx, "alice"); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		if _, err := s.LookupUser(ctx, "alice"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Errorf("deleted user found: %v", err)
		}
		if creds, err := s.ListCredentials(ctx, "alice"); err != nil || len(creds) != 0 {
			t.Errorf("alice's credentials = %d, %v; want 0", len(creds), err)
		}
		if creds, err := s.ListCredentials(ctx, "bob"); err != nil || len(creds) != 1 {
			t.Errorf("bob's credentials = %d, %v; want 1", len(creds), err)
		}
		// Deleting again, or an unknown user, is not an error.
		if err := s.DeleteUser(ctx, "alice"); err != nil {
			t.Errorf("second DeleteUser: %v", err)
		}
		// A new identity gets a new handle.
		if u, err := s.EnsureUser(ctx, "alice", "", ""); err != nil || len(u.Handle) == 0 {
			t.Errorf("EnsureUser after delete = %+v, %v", u, err)
		}
	})
}

func TestUserMethodsReportDatabaseErrors(t *testing.T) {
	s := brokenStore(t)
	ctx := context.Background()
	for name, err := range map[string]error{
		"LookupUser": func() error { _, err := s.LookupUser(ctx, "alice"); return err }(),
		"LookupUserByHandle": func() error {
			_, err := s.LookupUserByHandle(ctx, []byte("h"))
			return err
		}(),
		"EnsureUser": func() error { _, err := s.EnsureUser(ctx, "alice", "", ""); return err }(),
		"DeleteUser": s.DeleteUser(ctx, "alice"),
		"Migrate":    s.Migrate(ctx),
	} {
		if err == nil || errors.Is(err, auth.ErrUserNotFound) {
			t.Errorf("%s err = %v, want a database error", name, err)
		}
	}
}

func TestDeleteUserRollsBack(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		if _, err := s.EnsureUser(ctx, "alice", "", ""); err != nil {
			t.Fatal(err)
		}
		mustCreateCredential(t, s, newCredential("alice"))
		restore := failOn(t, db, "delete", User{}.TableName())
		err := s.DeleteUser(ctx, "alice")
		restore()
		if err == nil {
			t.Fatal("DeleteUser succeeded despite the injected failure")
		}
		if creds, err := s.ListCredentials(ctx, "alice"); err != nil || len(creds) != 1 {
			t.Errorf("credentials after failed delete = %d, %v; want 1", len(creds), err)
		}
	})
}

func TestOptions(t *testing.T) {
	if got := len(New(nil).Options()); got != 3 {
		t.Fatalf("len(Options()) = %d, want 3", got)
	}
}

func assertUser(t *testing.T, got, want passkey.User) {
	t.Helper()
	if got.Subject != want.Subject || !bytes.Equal(got.Handle, want.Handle) || got.Name != want.Name || got.DisplayName != want.DisplayName {
		t.Errorf("user = %+v, want %+v", got, want)
	}
}
