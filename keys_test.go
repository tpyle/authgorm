package authgorm

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
)

func TestKeyRoundTrip(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		local := time.FixedZone("UTC+5", 5*3600)
		keys := map[uuid.UUID]*auth.VerificationKey{}
		for _, k := range []*auth.VerificationKey{
			newKey(t, baseTime, baseTime.Add(48*time.Hour)),
			newKey(t, baseTime.Add(time.Hour), time.Time{}), // never expires
			newKey(t, baseTime.In(local), baseTime.Add(time.Hour).In(local)),
		} {
			if err := s.StoreKey(ctx, k); err != nil {
				t.Fatalf("StoreKey: %v", err)
			}
			keys[k.ID] = k
		}

		got, err := s.ListKeys(ctx)
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(got) != len(keys) {
			t.Fatalf("ListKeys returned %d keys, want %d", len(got), len(keys))
		}
		for _, g := range got {
			want, ok := keys[g.ID]
			if !ok {
				t.Fatalf("unexpected key %s", g.ID)
			}
			if !g.PublicKey.Equal(want.PublicKey) {
				t.Errorf("key %s: public key differs", g.ID)
			}
			if !g.CreatedAt.Equal(want.CreatedAt) {
				t.Errorf("key %s: CreatedAt = %v, want %v", g.ID, g.CreatedAt, want.CreatedAt)
			}
			if !g.ExpiresAt.Equal(want.ExpiresAt) || g.ExpiresAt.IsZero() != want.ExpiresAt.IsZero() {
				t.Errorf("key %s: ExpiresAt = %v, want %v", g.ID, g.ExpiresAt, want.ExpiresAt)
			}
		}
	})
}

func TestListKeysEmpty(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		got, err := s.ListKeys(context.Background())
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("ListKeys returned %d keys, want 0", len(got))
		}
	})
}

func TestStoreKeyErrors(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		noPub := &auth.VerificationKey{ID: uuid.New(), CreatedAt: baseTime}
		if err := s.StoreKey(ctx, noPub); err == nil {
			t.Error("StoreKey accepted a key without a public key")
		}
		k := newKey(t, baseTime, time.Time{})
		if err := s.StoreKey(ctx, k); err != nil {
			t.Fatal(err)
		}
		if err := s.StoreKey(ctx, k); err == nil {
			t.Error("StoreKey accepted a duplicate ID")
		}
		if n := countRows(t, db, &SigningKey{}); n != 1 {
			t.Errorf("keys = %d, want 1", n)
		}
	})
}

func TestListKeysRejectsCorruptRows(t *testing.T) {
	good := func(t *testing.T) []byte {
		der, err := newKey(t, baseTime, time.Time{}).MarshalPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	tests := []struct {
		name string
		row  func(t *testing.T) SigningKey
	}{
		{"bad id", func(t *testing.T) SigningKey {
			return SigningKey{ID: "not-a-uuid", PublicKey: good(t), CreatedAt: baseTime}
		}},
		{"bad public key", func(t *testing.T) SigningKey {
			return SigningKey{ID: uuid.NewString(), PublicKey: []byte("garbage"), CreatedAt: baseTime}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
				row := tt.row(t)
				if err := db.Create(&row).Error; err != nil {
					t.Fatal(err)
				}
				if _, err := s.ListKeys(context.Background()); err == nil {
					t.Fatal("ListKeys accepted a corrupt row")
				}
			})
		})
	}
}

func TestDeleteKeys(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		var ids []uuid.UUID
		for range 4 {
			k := newKey(t, baseTime, baseTime.Add(time.Hour))
			if err := s.StoreKey(ctx, k); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, k.ID)
		}

		if err := s.DeleteKeys(ctx, nil); err != nil {
			t.Fatalf("DeleteKeys(nil): %v", err)
		}
		if err := s.DeleteKeys(ctx, []uuid.UUID{}); err != nil {
			t.Fatalf("DeleteKeys(empty): %v", err)
		}
		// Missing IDs are ignored, existing ones deleted.
		if err := s.DeleteKeys(ctx, []uuid.UUID{ids[0], uuid.New(), ids[2]}); err != nil {
			t.Fatalf("DeleteKeys: %v", err)
		}
		// Deleting already-deleted keys again is not an error.
		if err := s.DeleteKeys(ctx, []uuid.UUID{ids[0]}); err != nil {
			t.Fatalf("DeleteKeys again: %v", err)
		}

		got, err := s.ListKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		left := map[uuid.UUID]bool{}
		for _, k := range got {
			left[k.ID] = true
		}
		if len(left) != 2 || !left[ids[1]] || !left[ids[3]] {
			t.Fatalf("remaining keys = %v, want %s and %s", left, ids[1], ids[3])
		}
		// Rows are deleted, not soft-deleted.
		if n := countRows(t, db.Unscoped(), &SigningKey{}); n != 2 {
			t.Errorf("rows = %d, want 2", n)
		}
	})
}

func TestKeyMethodsReportDatabaseErrors(t *testing.T) {
	s := brokenStore(t)
	ctx := context.Background()
	if err := s.StoreKey(ctx, newKey(t, baseTime, time.Time{})); err == nil {
		t.Error("StoreKey succeeded on a closed database")
	}
	if _, err := s.ListKeys(ctx); err == nil {
		t.Error("ListKeys succeeded on a closed database")
	}
	if err := s.DeleteKeys(ctx, []uuid.UUID{uuid.New()}); err == nil {
		t.Error("DeleteKeys succeeded on a closed database")
	}
}
