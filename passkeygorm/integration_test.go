package passkeygorm

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/tpyle/auth/passkey"
	"github.com/tpyle/auth/v2"
	"github.com/tpyle/authgorm"
	"gorm.io/gorm"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

// env is a passkey service and Authorizer sharing one database.
type env struct {
	t     *testing.T
	store *Store
	auth  *auth.Authorizer
	clock *fakeClock
	va    *virtualAuthenticator
}

func newEnv(t *testing.T, db *gorm.DB) *env {
	t.Helper()
	ctx := context.Background()
	// Microseconds are the finest precision every backend stores.
	e := &env{t: t, clock: &fakeClock{now: time.Now().Truncate(time.Microsecond)}, va: newVirtualAuthenticator(t, testOrigin)}
	e.store = New(db, WithClock(e.clock.Now))
	if err := e.store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	core := authgorm.New(db)
	if err := core.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(ctx, append(core.Options(), auth.WithClock(e.clock.Now))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	e.auth = a
	return e
}

// passkeys returns a new passkey service on the shared store, as a separate
// instance of the application would have.
func (e *env) passkeys(opts ...passkey.Option) *passkey.Passkeys {
	e.t.Helper()
	all := append(e.store.Options(),
		passkey.WithRelyingParty(testRPID, "Example", testOrigin),
		passkey.WithTokenIssuer(e.auth),
		passkey.WithClock(e.clock.Now),
		passkey.WithLogger(slog.New(slog.DiscardHandler)),
	)
	p, err := passkey.New(append(all, opts...)...)
	if err != nil {
		e.t.Fatalf("passkey.New: %v", err)
	}
	return p
}

func (e *env) register(p *passkey.Passkeys, subject string) *virtualCredential {
	e.t.Helper()
	ctx := context.Background()
	if _, err := e.store.EnsureUser(ctx, subject, subject+"@example.com", ""); err != nil {
		e.t.Fatal(err)
	}
	ch, err := p.BeginRegistration(ctx, subject)
	if err != nil {
		e.t.Fatalf("BeginRegistration: %v", err)
	}
	resp, cred := e.va.create(ch)
	if _, err := p.FinishRegistration(ctx, subject, ch.CeremonyID, resp, "test key"); err != nil {
		e.t.Fatalf("FinishRegistration: %v", err)
	}
	return cred
}

func TestPasskeyEndToEnd(t *testing.T) {
	forEachBackend(t, func(t *testing.T, _ *Store, db *gorm.DB) {
		ctx := context.Background()
		e := newEnv(t, db)
		instanceA, instanceB := e.passkeys(), e.passkeys()

		cred := e.register(instanceA, "alice")
		e.register(instanceA, "bob")

		// Begin on one instance, finish on another.
		ch, err := instanceA.BeginLogin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		resp := e.va.get(ch, cred, true)
		pair, err := instanceB.FinishLogin(ctx, ch.CeremonyID, resp)
		if err != nil {
			t.Fatalf("FinishLogin: %v", err)
		}
		claims, err := e.auth.VerifyAccessToken(ctx, pair.AccessToken)
		if err != nil || claims.Subject != "alice" {
			t.Fatalf("access token subject = %v, %v; want alice", claims, err)
		}
		if _, err := e.auth.Refresh(ctx, pair.RefreshToken); err != nil {
			t.Fatalf("Refresh after passkey login: %v", err)
		}

		// The ceremony is single use, even on another instance.
		if _, err := instanceA.FinishLogin(ctx, ch.CeremonyID, resp); !errors.Is(err, passkey.ErrInvalidCeremony) {
			t.Fatalf("replayed ceremony: err = %v, want ErrInvalidCeremony", err)
		}

		creds, err := instanceB.ListCredentials(ctx, "alice")
		if err != nil || len(creds) != 1 {
			t.Fatalf("ListCredentials = %d, %v; want 1", len(creds), err)
		}
		if !creds[0].LastUsedAt.Equal(e.clock.Now()) || creds[0].Label != "test key" {
			t.Errorf("credential = %+v, want label 'test key' and LastUsedAt now", creds[0])
		}

		// Re-authentication accepts only the signed-in user's passkey.
		ch, err = instanceA.BeginLoginFor(ctx, "bob")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := instanceA.AuthenticateFor(ctx, "bob", ch.CeremonyID, e.va.get(ch, cred, true)); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("alice's passkey for bob: err = %v, want ErrInvalidCredentials", err)
		}

		// A deleted passkey can no longer log in.
		if err := instanceA.DeleteCredential(ctx, "alice", cred.id); err != nil {
			t.Fatalf("DeleteCredential: %v", err)
		}
		ch, err = instanceA.BeginLogin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := instanceA.FinishLogin(ctx, ch.CeremonyID, e.va.get(ch, cred, true)); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("deleted passkey: err = %v, want ErrInvalidCredentials", err)
		}
	})
}

func TestPasskeyRegistrationErrors(t *testing.T) {
	forEachBackend(t, func(t *testing.T, _ *Store, db *gorm.DB) {
		ctx := context.Background()
		e := newEnv(t, db)
		p := e.passkeys()

		// A user without a WebAuthn identity cannot register.
		if _, err := p.BeginRegistration(ctx, "nobody"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("BeginRegistration(nobody): err = %v, want ErrUserNotFound", err)
		}

		// The same credential cannot be registered twice. The browser would
		// exclude it, so replay the response with a fresh ceremony's
		// challenge.
		cred := e.register(p, "alice")
		ch, err := p.BeginRegistration(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		var opts creationOptions
		mustUnmarshal(t, ch.Options, &opts)
		resp := e.va.attest(cred, opts.PublicKey.Challenge, "webauthn.create")
		if _, err := p.FinishRegistration(ctx, "alice", ch.CeremonyID, resp, "again"); !errors.Is(err, passkey.ErrCredentialExists) {
			t.Fatalf("duplicate registration: err = %v, want ErrCredentialExists", err)
		}
	})
}

func TestPasskeyCloneWarningIsStored(t *testing.T) {
	forEachBackend(t, func(t *testing.T, _ *Store, db *gorm.DB) {
		ctx := context.Background()
		e := newEnv(t, db)
		p := e.passkeys()
		e.va.useCounter = true
		cred := e.register(p, "alice")

		login := func() error {
			ch, err := p.BeginLogin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Authenticate(ctx, ch.CeremonyID, e.va.get(ch, cred, true))
			return err
		}
		for range 3 {
			if err := login(); err != nil {
				t.Fatalf("login: %v", err)
			}
		}
		e.va.counter = 1 // the counter goes backwards, as on a cloned key
		if err := login(); !errors.Is(err, passkey.ErrPossibleClone) {
			t.Fatalf("cloned login: err = %v, want ErrPossibleClone", err)
		}
		creds, err := e.store.ListCredentials(ctx, "alice")
		if err != nil || len(creds) != 1 {
			t.Fatalf("ListCredentials = %d, %v", len(creds), err)
		}
		if !creds[0].CloneWarning || creds[0].SignCount != 3 {
			t.Errorf("credential CloneWarning = %v, SignCount = %d; want true, 3", creds[0].CloneWarning, creds[0].SignCount)
		}
		// The warning persists: even a higher counter is refused.
		e.va.counter = 10
		if err := login(); !errors.Is(err, passkey.ErrPossibleClone) {
			t.Fatalf("login after clone warning: err = %v, want ErrPossibleClone", err)
		}
	})
}

func TestPasskeyCeremonyExpires(t *testing.T) {
	forEachBackend(t, func(t *testing.T, _ *Store, db *gorm.DB) {
		ctx := context.Background()
		e := newEnv(t, db)
		p := e.passkeys()
		cred := e.register(p, "alice")
		ch, err := p.BeginLogin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(10 * time.Minute)
		if _, err := p.FinishLogin(ctx, ch.CeremonyID, e.va.get(ch, cred, true)); !errors.Is(err, passkey.ErrInvalidCeremony) {
			t.Fatalf("expired ceremony: err = %v, want ErrInvalidCeremony", err)
		}
	})
}
