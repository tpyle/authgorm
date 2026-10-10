package passkeygorm

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"uuid"

	"github.com/tpyle/auth/passkey"
	"gorm.io/gorm"
)

func TestCeremonyRoundTrip(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		id := uuid.New()
		data := []byte(`{"challenge":"abc"}`)
		if err := s.SaveCeremony(ctx, id, data, baseTime.Add(5*time.Minute)); err != nil {
			t.Fatalf("SaveCeremony: %v", err)
		}
		if err := s.SaveCeremony(ctx, uuid.New(), []byte("other"), baseTime.Add(5*time.Minute)); err != nil {
			t.Fatal(err)
		}

		got, err := s.ConsumeCeremony(ctx, id, baseTime)
		if err != nil {
			t.Fatalf("ConsumeCeremony: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("data = %q, want %q", got, data)
		}
		// Single use.
		if _, err := s.ConsumeCeremony(ctx, id, baseTime); !errors.Is(err, passkey.ErrCeremonyNotFound) {
			t.Errorf("second consume: err = %v, want ErrCeremonyNotFound", err)
		}
		if _, err := s.ConsumeCeremony(ctx, uuid.New(), baseTime); !errors.Is(err, passkey.ErrCeremonyNotFound) {
			t.Errorf("unknown ceremony: err = %v, want ErrCeremonyNotFound", err)
		}
		if n := countRows(t, db, &Ceremony{}); n != 1 {
			t.Errorf("ceremonies = %d, want 1", n)
		}
	})
}

func TestConsumeExpiredCeremony(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		expiresAt := baseTime.Add(5 * time.Minute)
		for _, now := range []time.Time{expiresAt, expiresAt.Add(time.Second)} {
			id := uuid.New()
			if err := s.SaveCeremony(ctx, id, []byte("x"), expiresAt); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ConsumeCeremony(ctx, id, now); !errors.Is(err, passkey.ErrCeremonyNotFound) {
				t.Errorf("consume at %v: err = %v, want ErrCeremonyNotFound", now.Sub(expiresAt), err)
			}
		}
		// Expired ceremonies are deleted when consumed.
		if n := countRows(t, db, &Ceremony{}); n != 0 {
			t.Errorf("ceremonies = %d, want 0", n)
		}
	})
}

func TestSaveCeremonyRejectsDuplicateID(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		id := uuid.New()
		if err := s.SaveCeremony(ctx, id, []byte("a"), baseTime); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveCeremony(ctx, id, []byte("b"), baseTime); err == nil {
			t.Error("duplicate ceremony ID accepted")
		}
	})
}

// TestConcurrentConsumeCeremony checks that a ceremony is finished at most
// once when requests race.
func TestConcurrentConsumeCeremony(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		for range 10 {
			id := uuid.New()
			if err := s.SaveCeremony(ctx, id, []byte("x"), baseTime.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			const callers = 8
			errs := make([]error, callers)
			var wg sync.WaitGroup
			for i := range callers {
				wg.Go(func() { _, errs[i] = s.ConsumeCeremony(ctx, id, baseTime) })
			}
			wg.Wait()
			wins := 0
			for _, err := range errs {
				switch {
				case err == nil:
					wins++
				case !errors.Is(err, passkey.ErrCeremonyNotFound):
					t.Fatal(err)
				}
			}
			if wins != 1 {
				t.Fatalf("%d callers consumed the ceremony, want 1", wins)
			}
		}
	})
}

func TestPurgeExpiredCeremonies(t *testing.T) {
	for _, batch := range []int{1, 3, 1000} {
		forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
			ctx := context.Background()
			s.purgeBatchSize = batch
			s.purgeInterval = 0
			for i := range 7 {
				if err := s.SaveCeremony(ctx, uuid.New(), []byte("x"), baseTime.Add(time.Duration(i)*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			live := uuid.New()
			if err := s.SaveCeremony(ctx, live, []byte("live"), baseTime.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			// Nothing is purged at exactly its expiry.
			n, err := s.PurgeExpiredCeremonies(ctx, baseTime)
			if err != nil || n != 0 {
				t.Fatalf("purge at expiry = %d, %v; want 0, nil", n, err)
			}
			n, err = s.PurgeExpiredCeremonies(ctx, baseTime.Add(time.Minute).In(time.FixedZone("x", -3600)))
			if err != nil || n != 7 {
				t.Fatalf("purge = %d, %v; want 7, nil", n, err)
			}
			if _, err := s.ConsumeCeremony(ctx, live, baseTime); err != nil {
				t.Errorf("live ceremony purged: %v", err)
			}
		})
	}
}

func TestSaveCeremonyPurgesPeriodically(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		clock := &fakeClock{now: baseTime}
		s.now = clock.Now
		save := func(expiresAt time.Time) {
			t.Helper()
			if err := s.SaveCeremony(ctx, uuid.New(), []byte("x"), expiresAt); err != nil {
				t.Fatal(err)
			}
		}

		save(baseTime.Add(10 * time.Second)) // first save purges (nothing yet)
		clock.Advance(30 * time.Second)
		save(baseTime.Add(time.Hour)) // within the interval: no purge
		if n := countRows(t, db, &Ceremony{}); n != 2 {
			t.Fatalf("ceremonies = %d, want 2 (no purge within the interval)", n)
		}
		clock.Advance(31 * time.Second)
		save(baseTime.Add(time.Hour)) // interval passed: the first is purged
		if n := countRows(t, db, &Ceremony{}); n != 2 {
			t.Fatalf("ceremonies = %d, want 2 after purge", n)
		}

		// A clock that moves backwards purges immediately.
		save(baseTime.Add(30 * time.Second))
		clock.Set(baseTime.Add(-time.Minute))
		save(baseTime.Add(time.Hour))
		clock.Set(baseTime.Add(2 * time.Minute))
		save(baseTime.Add(time.Hour))
		if n := countRows(t, db, &Ceremony{}); n != 4 {
			t.Fatalf("ceremonies = %d, want 4", n)
		}
	})
}

func TestSaveCeremonyPurgeCanBeDisabled(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		s.purgeInterval = 0
		for range 3 {
			if err := s.SaveCeremony(ctx, uuid.New(), []byte("x"), time.Unix(0, 0)); err != nil {
				t.Fatal(err)
			}
		}
		if n := countRows(t, db, &Ceremony{}); n != 3 {
			t.Fatalf("ceremonies = %d, want 3", n)
		}
	})
}

func TestSaveCeremonyIgnoresPurgeFailure(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		defer failOn(t, db, "query", Ceremony{}.TableName())()
		if err := s.SaveCeremony(context.Background(), uuid.New(), []byte("x"), baseTime); err != nil {
			t.Fatalf("SaveCeremony failed because of its purge: %v", err)
		}
	})
}

func TestPurgeCeremoniesErrors(t *testing.T) {
	for _, op := range []string{"query", "delete"} {
		t.Run(op, func(t *testing.T) {
			forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
				s.purgeInterval = 0
				if err := s.SaveCeremony(context.Background(), uuid.New(), []byte("x"), baseTime); err != nil {
					t.Fatal(err)
				}
				defer failOn(t, db, op, Ceremony{}.TableName())()
				if _, err := s.PurgeExpiredCeremonies(context.Background(), baseTime.Add(time.Hour)); err == nil {
					t.Fatal("purge succeeded despite the injected failure")
				}
			})
		})
	}
}

func TestConsumeCeremonyDeleteError(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		id := uuid.New()
		if err := s.SaveCeremony(context.Background(), id, []byte("x"), baseTime.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		defer failOn(t, db, "delete", Ceremony{}.TableName())()
		_, err := s.ConsumeCeremony(context.Background(), id, baseTime)
		if err == nil || errors.Is(err, passkey.ErrCeremonyNotFound) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})
}

func TestCeremonyMethodsReportDatabaseErrors(t *testing.T) {
	s := brokenStore(t, WithCeremonyPurgeInterval(0))
	ctx := context.Background()
	if err := s.SaveCeremony(ctx, uuid.New(), []byte("x"), baseTime); err == nil {
		t.Error("SaveCeremony succeeded on a closed database")
	}
	if _, err := s.ConsumeCeremony(ctx, uuid.New(), baseTime); err == nil || errors.Is(err, passkey.ErrCeremonyNotFound) {
		t.Errorf("ConsumeCeremony err = %v, want a database error", err)
	}
	if _, err := s.PurgeExpiredCeremonies(ctx, baseTime); err == nil {
		t.Error("PurgeExpiredCeremonies succeeded on a closed database")
	}
}

func TestOptionsApply(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	s := New(nil, WithClock(clock.Now), WithCeremonyPurgeInterval(time.Hour))
	if s.purgeInterval != time.Hour || !s.now().Equal(baseTime) {
		t.Errorf("options not applied: interval %v, now %v", s.purgeInterval, s.now())
	}
}
