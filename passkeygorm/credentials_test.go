package passkeygorm

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"math"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tpyle/auth/passkey"
	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
)

// newCredential returns a credential with every field set.
func newCredential(subject string) passkey.Credential {
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return passkey.Credential{
		ID:                id,
		Subject:           subject,
		PublicKey:         []byte{0xa5, 0x01, 0x02, 0x03, 0x26},
		SignCount:         7,
		AAGUID:            bytes.Repeat([]byte{0xab}, 16),
		Transports:        []string{"internal", "hybrid"},
		AttestationType:   "none",
		AttestationFormat: "none",
		UserVerified:      true,
		BackupEligible:    true,
		BackupState:       true,
		Label:             "Work laptop",
		CreatedAt:         baseTime,
	}
}

// mustCreateCredential saves c, first giving its subject a passkey user if
// it has none.
func mustCreateCredential(t *testing.T, s *Store, c passkey.Credential) {
	t.Helper()
	if _, err := s.EnsureUser(context.Background(), c.Subject, "", ""); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if err := s.CreateCredential(context.Background(), c); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
}

func TestCredentialRoundTrip(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		full := newCredential("alice")
		full.LastUsedAt = baseTime.Add(time.Hour)
		full.CloneWarning = true
		full.SignCount = math.MaxUint32
		// A minimal credential: no AAGUID, transports, label or last use.
		minimal := passkey.Credential{
			ID: []byte{0x00, 0xff, 0x00}, Subject: "alice", PublicKey: []byte{1},
			CreatedAt: baseTime.Add(time.Minute).In(time.FixedZone("x", 3600)),
		}
		other := newCredential("bob")
		for _, c := range []passkey.Credential{minimal, full, other} {
			mustCreateCredential(t, s, c)
		}

		got, err := s.ListCredentials(ctx, "alice")
		if err != nil {
			t.Fatalf("ListCredentials: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d credentials, want 2", len(got))
		}
		// Ordered by CreatedAt.
		assertCredential(t, got[0], full)
		assertCredential(t, got[1], minimal)

		if got, err := s.ListCredentials(ctx, "nobody"); err != nil || len(got) != 0 {
			t.Errorf("ListCredentials(nobody) = %d, %v; want 0, nil", len(got), err)
		}
	})
}

func TestCreateCredentialRejectsDuplicates(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		c := newCredential("alice")
		mustCreateCredential(t, s, c)

		if _, err := s.EnsureUser(ctx, "bob", "", ""); err != nil {
			t.Fatal(err)
		}
		dup := newCredential("bob")
		dup.ID = c.ID
		for _, d := range []passkey.Credential{c, dup} {
			if err := s.CreateCredential(ctx, d); !errors.Is(err, passkey.ErrCredentialExists) {
				t.Errorf("duplicate for %s: err = %v, want ErrCredentialExists", d.Subject, err)
			}
		}
		if err := s.CreateCredential(ctx, passkey.Credential{Subject: "alice"}); err == nil {
			t.Error("credential without ID accepted")
		}
		if n := countRows(t, db, &Credential{}); n != 1 {
			t.Errorf("credentials = %d, want 1", n)
		}
	})
}

func TestCreateCredentialRequiresUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		err := s.CreateCredential(context.Background(), newCredential("nobody"))
		if !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("err = %v, want ErrUserNotFound", err)
		}
		if n := countRows(t, db, &Credential{}); n != 0 {
			t.Errorf("credentials = %d, want 0", n)
		}
	})
}

// TestCreateCredentialRacesDeleteUser checks that a registration finishing
// while its user is deleted never leaves a credential behind.
func TestCreateCredentialRacesDeleteUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		for range 20 {
			if _, err := s.EnsureUser(ctx, "bob", "", ""); err != nil {
				t.Fatal(err)
			}
			var createErr, deleteErr error
			var wg sync.WaitGroup
			wg.Go(func() { createErr = s.CreateCredential(ctx, newCredential("bob")) })
			wg.Go(func() { deleteErr = s.DeleteUser(ctx, "bob") })
			wg.Wait()
			if deleteErr != nil {
				t.Fatalf("DeleteUser: %v", deleteErr)
			}
			if createErr != nil && !errors.Is(createErr, auth.ErrUserNotFound) {
				t.Fatalf("CreateCredential: %v", createErr)
			}
			if n := countRows(t, db, &Credential{}); n != 0 {
				t.Fatalf("%d credentials left behind for a deleted user", n)
			}
		}
	})
}

func TestCreateCredentialInsertError(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		if _, err := s.EnsureUser(context.Background(), "alice", "", ""); err != nil {
			t.Fatal(err)
		}
		defer failOn(t, db, "create", Credential{}.TableName())()
		err := s.CreateCredential(context.Background(), newCredential("alice"))
		if err == nil || errors.Is(err, passkey.ErrCredentialExists) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})
}

func TestRecordCredentialUse(t *testing.T) {
	later := baseTime.Add(time.Hour)
	tests := []struct {
		name   string
		start  func(*passkey.Credential)
		use    passkey.CredentialUse
		expect func(*passkey.Credential)
	}{
		{
			name: "counter rises",
			use:  passkey.CredentialUse{SignCount: 9, BackupState: true, UsedAt: later},
			expect: func(c *passkey.Credential) {
				c.SignCount = 9
				c.LastUsedAt = later
			},
		},
		{
			name:   "counter never falls",
			use:    passkey.CredentialUse{SignCount: 3, BackupState: true, UsedAt: later},
			expect: func(c *passkey.Credential) { c.LastUsedAt = later },
		},
		{
			name:  "user verification stays set",
			start: func(c *passkey.Credential) { c.UserVerified = true },
			use:   passkey.CredentialUse{SignCount: 7, BackupState: true, UserVerified: false, UsedAt: later},
			expect: func(c *passkey.Credential) {
				c.LastUsedAt = later
			},
		},
		{
			name:  "user verification gets set",
			start: func(c *passkey.Credential) { c.UserVerified = false },
			use:   passkey.CredentialUse{SignCount: 7, BackupState: true, UserVerified: true, UsedAt: later},
			expect: func(c *passkey.Credential) {
				c.UserVerified = true
				c.LastUsedAt = later
			},
		},
		{
			name:  "clone warning stays set",
			start: func(c *passkey.Credential) { c.CloneWarning = true },
			use:   passkey.CredentialUse{SignCount: 8, BackupState: true, UsedAt: later},
			expect: func(c *passkey.Credential) {
				c.SignCount = 8
				c.LastUsedAt = later
			},
		},
		{
			name: "refused login records only the warning",
			use:  passkey.CredentialUse{SignCount: 2, BackupState: true, CloneWarning: true},
			expect: func(c *passkey.Credential) {
				c.CloneWarning = true
			},
		},
		{
			name: "backup state follows the authenticator",
			use:  passkey.CredentialUse{SignCount: 7, BackupState: false, UsedAt: later},
			expect: func(c *passkey.Credential) {
				c.BackupState = false
				c.LastUsedAt = later
			},
		},
		{
			name:  "zero counter",
			start: func(c *passkey.Credential) { c.SignCount = 0 },
			use:   passkey.CredentialUse{SignCount: 0, BackupState: true, UsedAt: later},
			expect: func(c *passkey.Credential) {
				c.LastUsedAt = later
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
				c := newCredential("alice")
				if tt.start != nil {
					tt.start(&c)
				}
				mustCreateCredential(t, s, c)
				other := newCredential("alice")
				other.CreatedAt = baseTime.Add(time.Second)
				mustCreateCredential(t, s, other)

				u := tt.use
				u.ID = c.ID
				if err := s.RecordCredentialUse(context.Background(), u); err != nil {
					t.Fatalf("RecordCredentialUse: %v", err)
				}
				want := c
				tt.expect(&want)
				got, err := s.ListCredentials(context.Background(), "alice")
				if err != nil || len(got) != 2 {
					t.Fatalf("ListCredentials = %d, %v", len(got), err)
				}
				assertCredential(t, got[0], want)
				assertCredential(t, got[1], other) // untouched
			})
		})
	}
}

func TestRecordCredentialUseMissing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		u := passkey.CredentialUse{ID: []byte("gone"), SignCount: 1, UsedAt: baseTime}
		if err := s.RecordCredentialUse(context.Background(), u); err != nil {
			t.Fatalf("RecordCredentialUse on a missing credential: %v", err)
		}
	})
}

// TestRecordCredentialUseConcurrent checks that racing logins leave the
// highest counter, whatever order they commit in.
func TestRecordCredentialUseConcurrent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		c := newCredential("alice")
		c.SignCount = 0
		mustCreateCredential(t, s, c)
		var wg sync.WaitGroup
		errs := make([]error, 20)
		for i := range 20 {
			wg.Go(func() {
				errs[i] = s.RecordCredentialUse(context.Background(), passkey.CredentialUse{
					ID: c.ID, SignCount: uint32(i + 1), UserVerified: i == 7, UsedAt: baseTime,
				})
			})
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.ListCredentials(context.Background(), "alice")
		if err != nil || len(got) != 1 {
			t.Fatalf("ListCredentials = %d, %v", len(got), err)
		}
		if got[0].SignCount != 20 || !got[0].UserVerified {
			t.Errorf("after racing uses: SignCount = %d, UserVerified = %v; want 20, true", got[0].SignCount, got[0].UserVerified)
		}
	})
}

func TestDeleteCredential(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		alice := newCredential("alice")
		bob := newCredential("bob")
		mustCreateCredential(t, s, alice)
		mustCreateCredential(t, s, bob)

		// One user cannot delete another's credential.
		if err := s.DeleteCredential(ctx, "alice", bob.ID); !errors.Is(err, passkey.ErrCredentialNotFound) {
			t.Errorf("deleting bob's credential as alice: err = %v, want ErrCredentialNotFound", err)
		}
		if err := s.DeleteCredential(ctx, "alice", []byte("missing")); !errors.Is(err, passkey.ErrCredentialNotFound) {
			t.Errorf("deleting a missing credential: err = %v, want ErrCredentialNotFound", err)
		}
		if err := s.DeleteCredential(ctx, "alice", alice.ID); err != nil {
			t.Fatalf("DeleteCredential: %v", err)
		}
		if err := s.DeleteCredential(ctx, "alice", alice.ID); !errors.Is(err, passkey.ErrCredentialNotFound) {
			t.Errorf("second delete: err = %v, want ErrCredentialNotFound", err)
		}
		if got, _ := s.ListCredentials(ctx, "bob"); len(got) != 1 {
			t.Errorf("bob has %d credentials, want 1", len(got))
		}
		// The ID can be registered again once deleted.
		mustCreateCredential(t, s, alice)
	})
}

func TestListCredentialsRejectsCorruptSignCount(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		mustCreateCredential(t, s, newCredential("alice"))
		if err := db.Model(&Credential{}).Where("subject = ?", "alice").Update("sign_count", -1).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.ListCredentials(context.Background(), "alice"); err == nil {
			t.Fatal("ListCredentials accepted a negative sign count")
		}
	})
}

func TestCredentialMethodsReportDatabaseErrors(t *testing.T) {
	s := brokenStore(t)
	ctx := context.Background()
	if _, err := s.ListCredentials(ctx, "alice"); err == nil {
		t.Error("ListCredentials succeeded on a closed database")
	}
	if err := s.CreateCredential(ctx, newCredential("alice")); err == nil || errors.Is(err, passkey.ErrCredentialExists) {
		t.Errorf("CreateCredential err = %v, want a database error", err)
	}
	if err := s.RecordCredentialUse(ctx, passkey.CredentialUse{ID: []byte("x")}); err == nil {
		t.Error("RecordCredentialUse succeeded on a closed database")
	}
	if err := s.DeleteCredential(ctx, "alice", []byte("x")); err == nil || errors.Is(err, passkey.ErrCredentialNotFound) {
		t.Errorf("DeleteCredential err = %v, want a database error", err)
	}
}

func assertCredential(t *testing.T, got, want passkey.Credential) {
	t.Helper()
	if !bytes.Equal(got.ID, want.ID) || got.Subject != want.Subject || !bytes.Equal(got.PublicKey, want.PublicKey) ||
		got.SignCount != want.SignCount || !bytes.Equal(got.AAGUID, want.AAGUID) ||
		!slices.Equal(got.Transports, want.Transports) ||
		got.AttestationType != want.AttestationType || got.AttestationFormat != want.AttestationFormat ||
		got.UserVerified != want.UserVerified || got.BackupEligible != want.BackupEligible ||
		got.BackupState != want.BackupState || got.CloneWarning != want.CloneWarning || got.Label != want.Label {
		t.Errorf("credential =\n%+v\nwant\n%+v", got, want)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.LastUsedAt.Equal(want.LastUsedAt) {
		t.Errorf("credential times = %v/%v, want %v/%v", got.CreatedAt, got.LastUsedAt, want.CreatedAt, want.LastUsedAt)
	}
}
