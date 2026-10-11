package authgorm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func TestConsumeRefreshToken(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		parent := loginRecord("alice", baseTime, time.Hour)
		mustCreate(t, s, parent)
		child := childRecord(parent, baseTime.Add(time.Minute), time.Hour)
		mustCreate(t, s, child)

		first := baseTime.Add(2 * time.Minute)
		got, err := s.ConsumeRefreshToken(ctx, child.ID, first)
		if err != nil {
			t.Fatalf("first consume: %v", err)
		}
		assertRecord(t, got, child)
		if got.Used() {
			t.Fatalf("first consume returned UsedAt %v, want zero", got.UsedAt)
		}

		// Later calls see the first use time, which is never overwritten.
		for _, now := range []time.Time{first.Add(time.Second), first.Add(-time.Second)} {
			got, err = s.ConsumeRefreshToken(ctx, child.ID, now)
			if err != nil {
				t.Fatalf("second consume: %v", err)
			}
			want := child
			want.UsedAt = first
			assertRecord(t, got, want)
		}

		// The parent is a separate record and still unused.
		got, err = s.ConsumeRefreshToken(ctx, parent.ID, first)
		if err != nil {
			t.Fatal(err)
		}
		if got.Used() || got.ParentID != uuid.Nil {
			t.Errorf("parent = %+v, want unused with nil ParentID", got)
		}
	})
}

func TestConsumeRefreshTokenNotFound(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		_, err := s.ConsumeRefreshToken(context.Background(), uuid.New(), baseTime)
		if !errors.Is(err, auth.ErrRefreshTokenNotFound) {
			t.Fatalf("err = %v, want ErrRefreshTokenNotFound", err)
		}
	})
}

func TestConsumeRefreshTokenCorruptRows(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RefreshToken)
	}{
		{"bad parent", func(r *RefreshToken) { r.ParentID = "bad" }},
		{"bad family", func(r *RefreshToken) { r.FamilyID = "bad" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
				id := uuid.New()
				row := RefreshToken{
					ID: id.String(), ParentID: uuid.Nil.String(), FamilyID: uuid.NewString(),
					Subject: "alice", IssuedAt: baseTime, ExpiresAt: baseTime.Add(time.Hour),
				}
				tt.mutate(&row)
				if err := db.Create(&row).Error; err != nil {
					t.Fatal(err)
				}
				_, err := s.ConsumeRefreshToken(context.Background(), id, baseTime)
				if err == nil || errors.Is(err, auth.ErrRefreshTokenNotFound) {
					t.Fatalf("err = %v, want a parse error", err)
				}
			})
		})
	}
}

func TestCreateRefreshTokenExtendsFamily(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		parent := loginRecord("alice", baseTime, time.Hour)
		mustCreate(t, s, parent)
		assertFamilyExpiry(t, db, parent.FamilyID, parent.ExpiresAt)

		// A child that expires later extends the family.
		later := childRecord(parent, baseTime.Add(time.Minute), 2*time.Hour)
		mustCreate(t, s, later)
		assertFamilyExpiry(t, db, parent.FamilyID, later.ExpiresAt)

		// One that expires earlier does not shorten it.
		earlier := childRecord(later, baseTime.Add(2*time.Minute), time.Minute)
		mustCreate(t, s, earlier)
		assertFamilyExpiry(t, db, parent.FamilyID, later.ExpiresAt)

		if n := countRows(t, db, &RefreshToken{}); n != 3 {
			t.Errorf("tokens = %d, want 3", n)
		}
	})
}

func TestCreateRefreshTokenRejectsUnknownFamily(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		orphan := childRecord(loginRecord("alice", baseTime, time.Hour), baseTime, time.Hour)
		err := s.CreateRefreshToken(context.Background(), orphan)
		if !errors.Is(err, auth.ErrTokenRevoked) {
			t.Fatalf("err = %v, want ErrTokenRevoked", err)
		}
		if n := countRows(t, db, &RefreshToken{}); n != 0 {
			t.Errorf("tokens = %d, want 0", n)
		}
		if n := countRows(t, db, &RefreshFamily{}); n != 0 {
			t.Errorf("families = %d, want 0 (must not be recreated)", n)
		}
	})
}

func TestCreateRefreshTokenRejectsDuplicates(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		rec := loginRecord("alice", baseTime, time.Hour)
		mustCreate(t, s, rec)
		if err := s.CreateRefreshToken(ctx, rec); err == nil {
			t.Error("duplicate login record accepted")
		}
		child := childRecord(rec, baseTime, time.Hour)
		mustCreate(t, s, child)
		if err := s.CreateRefreshToken(ctx, child); err == nil {
			t.Error("duplicate child record accepted")
		}
	})
}

func TestRevokeRefreshTokenFamily(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		a1 := loginRecord("alice", baseTime, time.Hour)
		mustCreate(t, s, a1)
		a2 := childRecord(a1, baseTime, time.Hour)
		mustCreate(t, s, a2)
		other := loginRecord("alice", baseTime, time.Hour)
		mustCreate(t, s, other)

		if err := s.RevokeRefreshTokenFamily(ctx, a1.FamilyID); err != nil {
			t.Fatalf("RevokeRefreshTokenFamily: %v", err)
		}
		for _, id := range []uuid.UUID{a1.ID, a2.ID} {
			if _, err := s.ConsumeRefreshToken(ctx, id, baseTime); !errors.Is(err, auth.ErrRefreshTokenNotFound) {
				t.Errorf("consume revoked %s: err = %v, want ErrRefreshTokenNotFound", id, err)
			}
		}
		if _, err := s.ConsumeRefreshToken(ctx, other.ID, baseTime); err != nil {
			t.Errorf("other session affected: %v", err)
		}
		assertRevoked(t, db, a1.FamilyID, true)
		assertRevoked(t, db, other.FamilyID, false)

		// A refresh in the revoked family is rejected.
		err := s.CreateRefreshToken(ctx, childRecord(a2, baseTime, time.Hour))
		if !errors.Is(err, auth.ErrTokenRevoked) {
			t.Fatalf("create in revoked family: err = %v, want ErrTokenRevoked", err)
		}

		// Revoking again, or an unknown family, is not an error.
		if err := s.RevokeRefreshTokenFamily(ctx, a1.FamilyID); err != nil {
			t.Errorf("second revoke: %v", err)
		}
		if err := s.RevokeRefreshTokenFamily(ctx, uuid.New()); err != nil {
			t.Errorf("unknown family: %v", err)
		}
	})
}

func TestRevokeRefreshTokensForSubject(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		alice1 := loginRecord("alice", baseTime, time.Hour)
		alice2 := loginRecord("alice", baseTime, time.Hour)
		bob := loginRecord("bob", baseTime, time.Hour)
		for _, r := range []auth.RefreshTokenRecord{alice1, alice2, bob} {
			mustCreate(t, s, r)
		}
		alice3 := childRecord(alice1, baseTime, time.Hour)
		mustCreate(t, s, alice3)

		if err := s.RevokeRefreshTokensForSubject(ctx, "alice"); err != nil {
			t.Fatalf("RevokeRefreshTokensForSubject: %v", err)
		}
		for _, r := range []auth.RefreshTokenRecord{alice1, alice2, alice3} {
			if _, err := s.ConsumeRefreshToken(ctx, r.ID, baseTime); !errors.Is(err, auth.ErrRefreshTokenNotFound) {
				t.Errorf("alice token %s: err = %v, want ErrRefreshTokenNotFound", r.ID, err)
			}
			assertRevoked(t, db, r.FamilyID, true)
		}
		if _, err := s.ConsumeRefreshToken(ctx, bob.ID, baseTime); err != nil {
			t.Errorf("bob affected: %v", err)
		}
		assertRevoked(t, db, bob.FamilyID, false)

		if err := s.CreateRefreshToken(ctx, childRecord(alice3, baseTime, time.Hour)); !errors.Is(err, auth.ErrTokenRevoked) {
			t.Errorf("refresh after revoke: err = %v, want ErrTokenRevoked", err)
		}
		// A later login starts a fresh, valid session.
		mustCreate(t, s, loginRecord("alice", baseTime, time.Hour))

		for _, subject := range []string{"alice", "nobody", ""} {
			if err := s.RevokeRefreshTokensForSubject(ctx, subject); err != nil {
				t.Errorf("revoke %q again: %v", subject, err)
			}
		}
	})
}

func TestPurgeExpiredRefreshTokens(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		if n, err := s.PurgeExpiredRefreshTokens(ctx, baseTime); err != nil || n != 0 {
			t.Fatalf("purge empty store = %d, %v; want 0, nil", n, err)
		}

		// Family A: one token, expires at +1h.
		a1 := loginRecord("alice", baseTime, time.Hour)
		mustCreate(t, s, a1)
		// Family B: b1 expires at +1h, b2 at +2h30m, so the family lives on.
		b1 := loginRecord("bob", baseTime, time.Hour)
		mustCreate(t, s, b1)
		b2 := childRecord(b1, baseTime.Add(30*time.Minute), 2*time.Hour)
		mustCreate(t, s, b2)
		// Family C: revoked, expires at +3h. Its tombstone must survive.
		c1 := loginRecord("carol", baseTime, 3*time.Hour)
		mustCreate(t, s, c1)
		if err := s.RevokeRefreshTokenFamily(ctx, c1.FamilyID); err != nil {
			t.Fatal(err)
		}

		// Nothing is purged at exactly its expiry.
		if n, err := s.PurgeExpiredRefreshTokens(ctx, a1.ExpiresAt); err != nil || n != 0 {
			t.Fatalf("purge at expiry = %d, %v; want 0, nil", n, err)
		}

		n, err := s.PurgeExpiredRefreshTokens(ctx, baseTime.Add(2*time.Hour).In(time.FixedZone("x", -7*3600)))
		if err != nil {
			t.Fatalf("purge: %v", err)
		}
		if n != 3 { // a1, family A, b1
			t.Errorf("purged %d rows, want 3", n)
		}
		for _, id := range []uuid.UUID{a1.ID, b1.ID} {
			if _, err := s.ConsumeRefreshToken(ctx, id, baseTime); !errors.Is(err, auth.ErrRefreshTokenNotFound) {
				t.Errorf("token %s: err = %v, want ErrRefreshTokenNotFound", id, err)
			}
		}
		if _, err := s.ConsumeRefreshToken(ctx, b2.ID, baseTime); err != nil {
			t.Errorf("b2 purged early: %v", err)
		}
		assertRevoked(t, db, c1.FamilyID, true)

		// A stalled refresh into the purged family does not revive it.
		if err := s.CreateRefreshToken(ctx, childRecord(a1, baseTime, time.Hour)); !errors.Is(err, auth.ErrTokenRevoked) {
			t.Errorf("refresh into purged family: err = %v, want ErrTokenRevoked", err)
		}

		n, err = s.PurgeExpiredRefreshTokens(ctx, baseTime.Add(4*time.Hour))
		if err != nil || n != 3 { // b2, family B, family C
			t.Errorf("final purge = %d, %v; want 3, nil", n, err)
		}
		if c := countRows(t, db, &RefreshToken{}) + countRows(t, db, &RefreshFamily{}); c != 0 {
			t.Errorf("%d rows left, want 0", c)
		}
	})
}

func TestRefreshMethodsReportDatabaseErrors(t *testing.T) {
	s := brokenStore(t)
	ctx := context.Background()
	rec := loginRecord("alice", baseTime, time.Hour)
	if err := s.CreateRefreshToken(ctx, rec); err == nil {
		t.Error("CreateRefreshToken (login) succeeded on a closed database")
	}
	err := s.CreateRefreshToken(ctx, childRecord(rec, baseTime, time.Hour))
	if err == nil || errors.Is(err, auth.ErrTokenRevoked) {
		t.Errorf("CreateRefreshToken (refresh) err = %v, want a database error", err)
	}
	_, err = s.ConsumeRefreshToken(ctx, rec.ID, baseTime)
	if err == nil || errors.Is(err, auth.ErrRefreshTokenNotFound) {
		t.Errorf("ConsumeRefreshToken err = %v, want a database error", err)
	}
	if err := s.RevokeRefreshTokenFamily(ctx, rec.FamilyID); err == nil {
		t.Error("RevokeRefreshTokenFamily succeeded on a closed database")
	}
	if err := s.RevokeRefreshTokensForSubject(ctx, "alice"); err == nil {
		t.Error("RevokeRefreshTokensForSubject succeeded on a closed database")
	}
	if _, err := s.PurgeExpiredRefreshTokens(ctx, baseTime); err == nil {
		t.Error("PurgeExpiredRefreshTokens succeeded on a closed database")
	}
}

// TestConcurrentConsume checks that exactly one of many concurrent callers
// sees a token as unused, and that everyone else sees the winner's time.
func TestConcurrentConsume(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		const callers = 16
		for range 5 {
			rec := loginRecord("alice", baseTime, time.Hour)
			mustCreate(t, s, rec)

			results := make([]auth.RefreshTokenRecord, callers)
			errs := make([]error, callers)
			nows := make([]time.Time, callers)
			var wg sync.WaitGroup
			for i := range callers {
				nows[i] = baseTime.Add(time.Duration(i+1) * time.Second)
				wg.Go(func() {
					results[i], errs[i] = s.ConsumeRefreshToken(context.Background(), rec.ID, nows[i])
				})
			}
			wg.Wait()

			winner := -1
			for i, err := range errs {
				if err != nil {
					t.Fatalf("caller %d: %v", i, err)
				}
				if !results[i].Used() {
					if winner >= 0 {
						t.Fatalf("callers %d and %d both saw the token unused", winner, i)
					}
					winner = i
				}
			}
			if winner < 0 {
				t.Fatal("no caller saw the token unused")
			}
			for i, r := range results {
				if i != winner && !r.UsedAt.Equal(nows[winner]) {
					t.Errorf("caller %d saw UsedAt %v, want winner's %v", i, r.UsedAt, nows[winner])
				}
			}
		}
	})
}

// TestConcurrentRefreshAndRevoke checks that a refresh racing a family
// revocation is either rejected or deleted by it.
func TestConcurrentRefreshAndRevoke(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		for range 25 {
			parent := loginRecord("alice", baseTime, time.Hour)
			mustCreate(t, s, parent)
			child := childRecord(parent, baseTime, time.Hour)

			var createErr, revokeErr error
			var wg sync.WaitGroup
			wg.Go(func() { createErr = s.CreateRefreshToken(ctx, child) })
			wg.Go(func() { revokeErr = s.RevokeRefreshTokenFamily(ctx, parent.FamilyID) })
			wg.Wait()

			if revokeErr != nil {
				t.Fatalf("revoke: %v", revokeErr)
			}
			if createErr != nil && !errors.Is(createErr, auth.ErrTokenRevoked) {
				t.Fatalf("create: %v", createErr)
			}
			if _, err := s.ConsumeRefreshToken(ctx, child.ID, baseTime); !errors.Is(err, auth.ErrRefreshTokenNotFound) {
				t.Fatalf("child %s of family %s survived revocation (create err %v): consume err = %v", child.ID, child.FamilyID, createErr, err)
			}
		}
	})
}

// TestConcurrentLoginAndRevokeSubject checks that a login racing
// RevokeRefreshTokensForSubject ends up entirely before it (revoked) or
// entirely after it (a valid new session), never in between.
func TestConcurrentLoginAndRevokeSubject(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		for range 25 {
			rec := loginRecord("alice", baseTime, time.Hour)
			var createErr, revokeErr error
			var wg sync.WaitGroup
			wg.Go(func() { createErr = s.CreateRefreshToken(ctx, rec) })
			wg.Go(func() { revokeErr = s.RevokeRefreshTokensForSubject(ctx, "alice") })
			wg.Wait()
			if createErr != nil || revokeErr != nil {
				t.Fatalf("create err = %v, revoke err = %v", createErr, revokeErr)
			}

			var fam RefreshFamily
			if err := db.Where("id = ?", rec.FamilyID.String()).Take(&fam).Error; err != nil {
				t.Fatalf("family missing: %v", err)
			}
			_, err := s.ConsumeRefreshToken(ctx, rec.ID, baseTime)
			tokenExists := err == nil
			if err != nil && !errors.Is(err, auth.ErrRefreshTokenNotFound) {
				t.Fatal(err)
			}
			if fam.Revoked == tokenExists {
				t.Fatalf("inconsistent state: family revoked = %v, token exists = %v", fam.Revoked, tokenExists)
			}
		}
	})
}

func assertRecord(t *testing.T, got, want auth.RefreshTokenRecord) {
	t.Helper()
	if got.ID != want.ID || got.ParentID != want.ParentID || got.FamilyID != want.FamilyID || got.Subject != want.Subject {
		t.Errorf("record = %+v, want %+v", got, want)
	}
	if !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) || !got.UsedAt.Equal(want.UsedAt) {
		t.Errorf("record times = %v/%v/%v, want %v/%v/%v",
			got.IssuedAt, got.ExpiresAt, got.UsedAt, want.IssuedAt, want.ExpiresAt, want.UsedAt)
	}
}

func assertFamilyExpiry(t *testing.T, db *gorm.DB, id uuid.UUID, want time.Time) {
	t.Helper()
	var fam RefreshFamily
	if err := db.Where("id = ?", id.String()).Take(&fam).Error; err != nil {
		t.Fatalf("family %s: %v", id, err)
	}
	if !fam.ExpiresAt.Equal(want) {
		t.Errorf("family %s expires %v, want %v", id, fam.ExpiresAt, want)
	}
}

func assertRevoked(t *testing.T, db *gorm.DB, id uuid.UUID, want bool) {
	t.Helper()
	var fam RefreshFamily
	if err := db.Where("id = ?", id.String()).Take(&fam).Error; err != nil {
		t.Fatalf("family %s: %v", id, err)
	}
	if fam.Revoked != want {
		t.Errorf("family %s revoked = %v, want %v", id, fam.Revoked, want)
	}
}

// failOn makes every op ("query", "create", "update" or "delete") on table
// fail, to reach error paths after a transaction's first statement has
// succeeded. The returned function removes the failure.
func failOn(t *testing.T, db *gorm.DB, op, table string) (restore func()) {
	t.Helper()
	injected := errors.New("injected failure")
	fail := func(tx *gorm.DB) {
		if tx.Statement.Table == table {
			_ = tx.AddError(injected)
		}
	}
	name := "test:fail_" + op + "_" + table
	switch op {
	case "query":
		cb := db.Callback().Query()
		mustRegister(t, cb.Before("gorm:query").Register(name, fail))
		return func() { mustRegister(t, cb.Remove(name)) }
	case "create":
		cb := db.Callback().Create()
		mustRegister(t, cb.Before("gorm:create").Register(name, fail))
		return func() { mustRegister(t, cb.Remove(name)) }
	case "update":
		cb := db.Callback().Update()
		mustRegister(t, cb.Before("gorm:update").Register(name, fail))
		return func() { mustRegister(t, cb.Remove(name)) }
	case "delete":
		cb := db.Callback().Delete()
		mustRegister(t, cb.Before("gorm:delete").Register(name, fail))
		return func() { mustRegister(t, cb.Remove(name)) }
	}
	t.Fatalf("unknown op %q", op)
	return nil
}

func mustRegister(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshMethodsReportStatementErrors(t *testing.T) {
	tables := struct{ subjects, families, tokens string }{
		RefreshSubject{}.TableName(), RefreshFamily{}.TableName(), RefreshToken{}.TableName(),
	}
	tests := []struct {
		name      string
		op, table string
		call      func(s *Store, parent auth.RefreshTokenRecord) error
	}{
		{"login subject lock", "create", tables.subjects, func(s *Store, _ auth.RefreshTokenRecord) error {
			return s.CreateRefreshToken(context.Background(), loginRecord("bob", baseTime, time.Hour))
		}},
		{"login family insert", "create", tables.families, func(s *Store, _ auth.RefreshTokenRecord) error {
			return s.CreateRefreshToken(context.Background(), loginRecord("bob", baseTime, time.Hour))
		}},
		{"refresh family lock", "query", tables.families, func(s *Store, p auth.RefreshTokenRecord) error {
			return s.CreateRefreshToken(context.Background(), childRecord(p, baseTime, time.Hour))
		}},
		{"refresh family extension", "update", tables.families, func(s *Store, p auth.RefreshTokenRecord) error {
			return s.CreateRefreshToken(context.Background(), childRecord(p, baseTime, 2*time.Hour))
		}},
		{"refresh token insert", "create", tables.tokens, func(s *Store, p auth.RefreshTokenRecord) error {
			return s.CreateRefreshToken(context.Background(), childRecord(p, baseTime, time.Hour))
		}},
		{"consume update", "update", tables.tokens, func(s *Store, p auth.RefreshTokenRecord) error {
			_, err := s.ConsumeRefreshToken(context.Background(), p.ID, baseTime)
			return err
		}},
		{"revoke family mark", "update", tables.families, func(s *Store, p auth.RefreshTokenRecord) error {
			return s.RevokeRefreshTokenFamily(context.Background(), p.FamilyID)
		}},
		{"revoke family delete", "delete", tables.tokens, func(s *Store, p auth.RefreshTokenRecord) error {
			return s.RevokeRefreshTokenFamily(context.Background(), p.FamilyID)
		}},
		{"revoke subject lock", "create", tables.subjects, func(s *Store, p auth.RefreshTokenRecord) error {
			return s.RevokeRefreshTokensForSubject(context.Background(), p.Subject)
		}},
		{"revoke subject mark", "update", tables.families, func(s *Store, p auth.RefreshTokenRecord) error {
			return s.RevokeRefreshTokensForSubject(context.Background(), p.Subject)
		}},
		{"revoke subject delete", "delete", tables.tokens, func(s *Store, p auth.RefreshTokenRecord) error {
			return s.RevokeRefreshTokensForSubject(context.Background(), p.Subject)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
				parent := loginRecord("alice", baseTime, time.Hour)
				mustCreate(t, s, parent)
				restore := failOn(t, db, tt.op, tt.table)
				err := tt.call(s, parent)
				restore()
				if err == nil || errors.Is(err, auth.ErrTokenRevoked) || errors.Is(err, auth.ErrRefreshTokenNotFound) {
					t.Fatalf("err = %v, want the injected failure", err)
				}
				// Transactions roll back: the parent's session is intact.
				assertRevoked(t, db, parent.FamilyID, false)
				var row RefreshToken
				if err := db.Where("id = ?", parent.ID.String()).Take(&row).Error; err != nil {
					t.Errorf("parent token after failed call: %v", err)
				}
			})
		})
	}
}

func TestPurgeExpiredRefreshTokensInBatches(t *testing.T) {
	for _, batch := range []int{1, 3, 7, 1000} {
		t.Run(fmt.Sprintf("batch %d", batch), func(t *testing.T) {
			forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
				s.purgeBatchSize = batch
				for range 7 {
					mustCreate(t, s, loginRecord("alice", baseTime, time.Hour))
				}
				live := loginRecord("bob", baseTime, 3*time.Hour)
				mustCreate(t, s, live)

				n, err := s.PurgeExpiredRefreshTokens(context.Background(), baseTime.Add(2*time.Hour))
				if err != nil {
					t.Fatalf("purge: %v", err)
				}
				if n != 14 { // 7 tokens and 7 families
					t.Errorf("purged %d rows, want 14", n)
				}
				if c := countRows(t, db, &RefreshToken{}) + countRows(t, db, &RefreshFamily{}); c != 2 {
					t.Errorf("%d rows left, want 2 (bob's token and family)", c)
				}
			})
		})
	}
}

// TestPurgeStopsWhenNothingIsDeleted guards against an endless loop when
// selected rows cannot be deleted.
func TestPurgeStopsWhenNothingIsDeleted(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		s.purgeBatchSize = 1
		mustCreate(t, s, loginRecord("alice", baseTime, time.Hour))
		mustCreate(t, s, loginRecord("alice", baseTime, time.Hour))
		// Make every delete a no-op without reporting an error.
		cb := db.Callback().Delete()
		mustRegister(t, cb.Before("gorm:delete").Register("test:noop_delete", func(tx *gorm.DB) {
			tx.Statement.AddClause(clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: "1 = 0"}}})
		}))
		n, err := s.PurgeExpiredRefreshTokens(context.Background(), baseTime.Add(2*time.Hour))
		if err != nil || n != 0 {
			t.Fatalf("purge = %d, %v; want 0, nil", n, err)
		}
	})
}

func TestPurgeReportsStatementErrors(t *testing.T) {
	tables := []string{RefreshToken{}.TableName(), RefreshFamily{}.TableName()}
	for _, table := range tables {
		for _, op := range []string{"query", "delete"} {
			t.Run(op+" "+table, func(t *testing.T) {
				forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
					mustCreate(t, s, loginRecord("alice", baseTime, time.Hour))
					defer failOn(t, db, op, table)()
					if _, err := s.PurgeExpiredRefreshTokens(context.Background(), baseTime.Add(2*time.Hour)); err == nil {
						t.Fatal("purge succeeded despite the injected failure")
					}
				})
			})
		}
	}
}

func TestCreateRefreshTokenRejectsSubjectMismatch(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		login := loginRecord("alice", baseTime, time.Hour)
		mustCreate(t, s, login)
		child := childRecord(login, baseTime, time.Hour)
		child.Subject = "bob"
		if err := s.CreateRefreshToken(context.Background(), child); err == nil {
			t.Fatal("token for bob joined alice's family")
		}
		if n := countRows(t, db, &RefreshToken{}); n != 1 {
			t.Errorf("tokens = %d, want 1", n)
		}
	})
}
