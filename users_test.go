package authgorm

import (
	"context"
	"errors"
	"testing"

	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
)

func TestMigrateIsIdempotent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("second Migrate: %v", err)
		}
		for _, m := range allModels() {
			if !db.Migrator().HasTable(m) {
				t.Errorf("table for %T missing", m)
			}
		}
	})
}

func TestLookupPasswordHash(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		if err := db.Create(&User{UserSubject: "alice", HashedPassword: "hash-a"}).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&User{UserSubject: "bob", HashedPassword: "hash-b"}).Error; err != nil {
			t.Fatal(err)
		}

		tests := []struct {
			name     string
			username string
			want     string
			wantErr  error
		}{
			{"existing user", "alice", "hash-a", nil},
			{"other user", "bob", "hash-b", nil},
			{"unknown user", "carol", "", auth.ErrUserNotFound},
			{"empty username", "", "", auth.ErrUserNotFound},
			{"case sensitive", "ALICE", "", auth.ErrUserNotFound},
			{"sql metacharacters", "alice' OR '1'='1", "", auth.ErrUserNotFound},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := s.LookupPasswordHash(ctx, tt.username)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if got != tt.want {
					t.Errorf("hash = %q, want %q", got, tt.want)
				}
			})
		}
	})
}

func TestLookupPasswordHashSoftDeleted(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		if err := s.SetPasswordHash(ctx, "alice", "hash"); err != nil {
			t.Fatal(err)
		}
		if err := db.Where("user_subject = ?", "alice").Delete(&User{}).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.LookupPasswordHash(ctx, "alice"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("err = %v, want ErrUserNotFound", err)
		}
		// The name stays taken until the row is deleted permanently.
		if err := s.SetPasswordHash(ctx, "alice", "new"); err == nil {
			t.Fatal("SetPasswordHash on a soft-deleted username succeeded")
		}
		if err := db.Unscoped().Where("user_subject = ?", "alice").Delete(&User{}).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.SetPasswordHash(ctx, "alice", "new"); err != nil {
			t.Fatalf("SetPasswordHash after hard delete: %v", err)
		}
	})
}

func TestSetPasswordHash(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		if err := s.SetPasswordHash(ctx, "alice", "first"); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := s.SetPasswordHash(ctx, "alice", "second"); err != nil {
			t.Fatalf("replace: %v", err)
		}
		if err := s.SetPasswordHash(ctx, "bob", "other"); err != nil {
			t.Fatalf("create bob: %v", err)
		}
		// Setting the same hash again is a no-op update, not a duplicate insert.
		if err := s.SetPasswordHash(ctx, "bob", "other"); err != nil {
			t.Fatalf("same hash: %v", err)
		}
		if got, _ := s.LookupPasswordHash(ctx, "alice"); got != "second" {
			t.Errorf("alice hash = %q, want second", got)
		}
		if got, _ := s.LookupPasswordHash(ctx, "bob"); got != "other" {
			t.Errorf("bob hash = %q, want other", got)
		}
		if n := countRows(t, db, &User{}); n != 2 {
			t.Errorf("users = %d, want 2", n)
		}
	})
}

func TestUsernameIsUnique(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		if err := db.Create(&User{UserSubject: "alice", HashedPassword: "a"}).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&User{UserSubject: "alice", HashedPassword: "b"}).Error; err == nil {
			t.Fatal("duplicate username inserted")
		}
	})
}

func TestUpdatePasswordHash(t *testing.T) {
	tests := []struct {
		name     string
		username string
		oldHash  string
		want     string
	}{
		{"matching old hash", "alice", "old", "new"},
		{"stale old hash", "alice", "stale", "old"},
		{"unknown user", "nobody", "old", "old"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
				ctx := context.Background()
				if err := s.SetPasswordHash(ctx, "alice", "old"); err != nil {
					t.Fatal(err)
				}
				if err := s.UpdatePasswordHash(ctx, tt.username, tt.oldHash, "new"); err != nil {
					t.Fatalf("UpdatePasswordHash: %v", err)
				}
				if got, _ := s.LookupPasswordHash(ctx, "alice"); got != tt.want {
					t.Errorf("hash = %q, want %q", got, tt.want)
				}
				if n := countRows(t, db, &User{}); n != 1 {
					t.Errorf("users = %d, want 1", n)
				}
			})
		})
	}
}

func TestUserMethodsReportDatabaseErrors(t *testing.T) {
	s := brokenStore(t)
	ctx := context.Background()
	_, err := s.LookupPasswordHash(ctx, "alice")
	if err == nil || errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("LookupPasswordHash err = %v, want a non-not-found error", err)
	}
	if err := s.UpdatePasswordHash(ctx, "alice", "a", "b"); err == nil {
		t.Error("UpdatePasswordHash succeeded on a closed database")
	}
	if err := s.SetPasswordHash(ctx, "alice", "a"); err == nil {
		t.Error("SetPasswordHash succeeded on a closed database")
	}
	if err := s.Migrate(ctx); err == nil {
		t.Error("Migrate succeeded on a closed database")
	}
}

func TestContextIsPassedOn(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := s.LookupPasswordHash(ctx, "alice"); !errors.Is(err, context.Canceled) {
			t.Errorf("LookupPasswordHash err = %v, want context.Canceled", err)
		}
		if _, err := s.ListKeys(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("ListKeys err = %v, want context.Canceled", err)
		}
	})
}

func TestOptions(t *testing.T) {
	s := New(nil)
	if got := len(s.Options()); got != 3 {
		t.Fatalf("len(Options()) = %d, want 3", got)
	}
}
