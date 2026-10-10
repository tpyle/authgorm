package authgorm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
)

// cheapParams keeps Argon2 fast in tests.
var cheapParams = auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// testClock is a settable clock for auth.WithClock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newAuthorizer(t *testing.T, s *Store, clock *testClock, opts ...auth.Option) *auth.Authorizer {
	t.Helper()
	all := append(s.Options(),
		auth.WithArgon2Params(cheapParams),
		auth.WithClock(clock.Now),
		auth.WithRefreshReuseGrace(10*time.Second),
	)
	a, err := auth.New(context.Background(), append(all, opts...)...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return a
}

func TestAuthorizerEndToEnd(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		clock := &testClock{now: time.Now()}
		a := newAuthorizer(t, s, clock)

		hash, err := a.HashPassword(ctx, []byte("hunter2"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetPasswordHash(ctx, "alice", hash); err != nil {
			t.Fatal(err)
		}

		if _, err := a.Login(ctx, "alice", []byte("wrong")); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("wrong password: err = %v", err)
		}
		if _, err := a.Login(ctx, "bob", []byte("hunter2")); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("unknown user: err = %v", err)
		}
		pair, err := a.Login(ctx, "alice", []byte("hunter2"))
		if err != nil {
			t.Fatalf("Login: %v", err)
		}

		// Another instance sharing the database verifies the token.
		b := newAuthorizer(t, s, clock)
		claims, err := b.VerifyAccessToken(ctx, pair.AccessToken)
		if err != nil {
			t.Fatalf("second instance VerifyAccessToken: %v", err)
		}
		if claims.Subject != "alice" {
			t.Errorf("subject = %q, want alice", claims.Subject)
		}

		// Refresh rotates the token. A retry within the grace window works,
		// a reuse after it revokes the session.
		clock.Advance(time.Minute)
		pair2, err := b.Refresh(ctx, pair.RefreshToken)
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if _, err := a.Refresh(ctx, pair.RefreshToken); err != nil {
			t.Fatalf("Refresh within grace: %v", err)
		}
		clock.Advance(time.Minute)
		if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, auth.ErrRefreshTokenReused) {
			t.Fatalf("reuse after grace: err = %v, want ErrRefreshTokenReused", err)
		}
		if _, err := a.Refresh(ctx, pair2.RefreshToken); !errors.Is(err, auth.ErrTokenRevoked) {
			t.Fatalf("refresh in revoked session: err = %v, want ErrTokenRevoked", err)
		}

		// Logout ends one session.
		pair3, err := a.Login(ctx, "alice", []byte("hunter2"))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Logout(ctx, pair3.RefreshToken); err != nil {
			t.Fatalf("Logout: %v", err)
		}
		if _, err := a.Refresh(ctx, pair3.RefreshToken); !errors.Is(err, auth.ErrTokenRevoked) {
			t.Fatalf("refresh after logout: err = %v, want ErrTokenRevoked", err)
		}

		// RevokeAllSessions ends every session.
		p4, err := a.Login(ctx, "alice", []byte("hunter2"))
		if err != nil {
			t.Fatal(err)
		}
		p5, err := b.Login(ctx, "alice", []byte("hunter2"))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.RevokeAllSessions(ctx, "alice"); err != nil {
			t.Fatalf("RevokeAllSessions: %v", err)
		}
		for _, p := range []*auth.TokenPair{p4, p5} {
			if _, err := b.Refresh(ctx, p.RefreshToken); !errors.Is(err, auth.ErrTokenRevoked) {
				t.Fatalf("refresh after RevokeAllSessions: err = %v, want ErrTokenRevoked", err)
			}
		}

		jwks, err := a.JWKS(ctx)
		if err != nil {
			t.Fatalf("JWKS: %v", err)
		}
		if len(jwks.Keys) == 0 {
			t.Error("JWKS is empty")
		}
	})
}

func TestAuthorizerUpgradesPasswordHash(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		old := cheapParams
		old.Iterations = 2
		oldHash, err := auth.HashPassword([]byte("hunter2"), old)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetPasswordHash(ctx, "alice", oldHash); err != nil {
			t.Fatal(err)
		}

		a := newAuthorizer(t, s, &testClock{now: time.Now()})
		if err := a.Authenticate(ctx, "alice", []byte("hunter2")); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		newHash, err := s.LookupPasswordHash(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if newHash == oldHash {
			t.Fatal("hash was not upgraded")
		}
		if err := a.Authenticate(ctx, "alice", []byte("hunter2")); err != nil {
			t.Fatalf("Authenticate with upgraded hash: %v", err)
		}
	})
}

func TestAuthorizerSurvivesRestart(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		clock := &testClock{now: time.Now()}
		a, err := auth.New(ctx, append(s.Options(), auth.WithClock(clock.Now))...)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := a.IssueTokenPair(ctx, "alice", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}

		restarted := newAuthorizer(t, s, clock)
		if _, err := restarted.VerifyAccessToken(ctx, pair.AccessToken); err != nil {
			t.Fatalf("VerifyAccessToken after restart: %v", err)
		}
		if _, err := restarted.Refresh(ctx, pair.RefreshToken); err != nil {
			t.Fatalf("Refresh after restart: %v", err)
		}
	})
}

func TestAuthorizerPurgesRefreshTokens(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Store, db *gorm.DB) {
		ctx := context.Background()
		clock := &testClock{now: time.Now()}
		a := newAuthorizer(t, s, clock, auth.WithRefreshTokenTTL(time.Hour))
		if _, err := a.IssueTokenPair(ctx, "alice", nil); err != nil {
			t.Fatal(err)
		}
		clock.Advance(50 * time.Minute)
		live, err := a.IssueTokenPair(ctx, "bob", nil)
		if err != nil {
			t.Fatal(err)
		}

		// Alice's records expire at +60m. The Authorizer keeps them a few
		// minutes past that.
		clock.Advance(12 * time.Minute) // +62m
		if n, err := a.PurgeExpiredRefreshTokens(ctx); err != nil || n != 0 {
			t.Fatalf("purge within margin = %d, %v; want 0, nil", n, err)
		}
		clock.Advance(8 * time.Minute) // +70m
		n, err := a.PurgeExpiredRefreshTokens(ctx)
		if err != nil {
			t.Fatalf("PurgeExpiredRefreshTokens: %v", err)
		}
		if n != 2 { // alice's token and family
			t.Errorf("purged %d rows, want 2", n)
		}
		if c := countRows(t, db, &RefreshToken{}) + countRows(t, db, &RefreshFamily{}); c != 2 {
			t.Errorf("%d rows left, want 2", c)
		}
		if _, err := a.Refresh(ctx, live.RefreshToken); err != nil {
			t.Errorf("live session broken by purge: %v", err)
		}
	})
}
