// Command server is a small web app with password login, passkey
// registration and passwordless passkey login, keeping all of its state
// (users, signing keys, sessions, passkeys and ceremonies) in one SQLite
// database through authgorm and passkeygorm.
//
//	cd passkeygorm && go run ./examples/server [path/to/app.db]
//
// Then open http://localhost:8080, sign in with alice / password, register a
// passkey, sign out, and sign back in with the passkey. Restart the server
// in between: sessions and passkeys survive. Chrome's DevTools (More tools >
// WebAuthn) can emulate an authenticator if the machine has none.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"uuid"

	"github.com/tpyle/auth/passkey"
	"github.com/tpyle/auth/v2"
	"github.com/tpyle/authgorm"
	"github.com/tpyle/authgorm/passkeygorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

//go:embed index.html
var indexHTML []byte

const origin = "http://localhost:8080"

func main() {
	path := filepath.Join(os.TempDir(), "passkeygorm-example.db")
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open("file:"+path+"?_txlock=immediate&_busy_timeout=5000&_journal_mode=WAL"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	app, err := newApp(ctx, db, origin)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = app.auth.Close() }()
	if err := app.seed(ctx, "alice", "password"); err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{Addr: ":8080", Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second}
	slog.Info("open "+origin, "user", "alice", "password", "password", "database", path)
	log.Fatal(srv.ListenAndServe())
}

// app holds the services and their shared stores.
type app struct {
	auth     *auth.Authorizer
	passkeys *passkey.Passkeys
	users    *authgorm.Store    // passwords, keys and sessions
	pkStore  *passkeygorm.Store // passkey users, credentials and ceremonies
}

// newApp migrates db and creates the Authorizer and passkey service.
func newApp(ctx context.Context, db *gorm.DB, origin string, opts ...auth.Option) (*app, error) {
	users := authgorm.New(db)
	if err := users.Migrate(ctx); err != nil {
		return nil, err
	}
	pkStore := passkeygorm.New(db)
	if err := pkStore.Migrate(ctx); err != nil {
		return nil, err
	}
	a, err := auth.New(ctx, append(users.Options(), opts...)...)
	if err != nil {
		return nil, err
	}
	pk, err := passkey.New(append(pkStore.Options(),
		passkey.WithRelyingParty("localhost", "Passkey example", origin),
		passkey.WithTokenIssuer(a),
	)...)
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	return &app{auth: a, passkeys: pk, users: users, pkStore: pkStore}, nil
}

// seed creates a password user unless it already exists.
func (app *app) seed(ctx context.Context, username, password string) error {
	hash, err := app.auth.HashPassword(ctx, []byte(password))
	if err != nil {
		return err
	}
	if err := app.users.CreateUser(ctx, username, hash); !errors.Is(err, authgorm.ErrUserExists) {
		return err
	}
	return nil
}

func (app *app) routes() http.Handler {
	a, pk := app.auth, app.passkeys
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		pair, err := a.Login(r.Context(), req.Username, []byte(req.Password))
		reply(w, r, newTokenResponse(pair), err)
	})

	// Registration adds a passkey to the signed-in user. EnsureUser gives
	// the user a WebAuthn handle the first time.
	mux.Handle("POST /passkey/register/begin", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		if _, err := app.pkStore.EnsureUser(r.Context(), subject, subject, ""); err != nil {
			reply(w, r, nil, err)
			return
		}
		ch, err := pk.BeginRegistration(r.Context(), subject)
		reply(w, r, ch, err)
	})))
	mux.Handle("POST /passkey/register/finish", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		var req finishRequest
		if !readJSON(w, r, &req) {
			return
		}
		cred, err := pk.FinishRegistration(r.Context(), subject, req.CeremonyID, req.Credential, req.Label)
		var resp map[string]any
		if err == nil {
			resp = map[string]any{"label": cred.Label, "synced": cred.BackupEligible}
		}
		reply(w, r, resp, err)
	})))
	mux.Handle("GET /passkeys", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		creds, err := pk.ListCredentials(r.Context(), subject)
		out := []map[string]any{}
		for _, c := range creds {
			out = append(out, map[string]any{"label": c.Label, "created_at": c.CreatedAt, "last_used_at": c.LastUsedAt})
		}
		reply(w, r, out, err)
	})))

	// Login needs no username: the authenticator says who the user is.
	mux.HandleFunc("POST /passkey/login/begin", func(w http.ResponseWriter, r *http.Request) {
		ch, err := pk.BeginLogin(r.Context())
		reply(w, r, ch, err)
	})
	mux.HandleFunc("POST /passkey/login/finish", func(w http.ResponseWriter, r *http.Request) {
		var req finishRequest
		if !readJSON(w, r, &req) {
			return
		}
		pair, err := pk.FinishLogin(r.Context(), req.CeremonyID, req.Credential)
		reply(w, r, newTokenResponse(pair), err)
	})

	mux.Handle("GET /me", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]string{"subject": subject})
	})))
	return mux
}

// finishRequest is the body of both Finish endpoints.
type finishRequest struct {
	CeremonyID uuid.UUID `json:"ceremonyId"`
	// Credential is the browser's PublicKeyCredential, from toJSON().
	Credential json.RawMessage `json:"credential"`
	// Label names a new passkey; registration only.
	Label string `json:"label"`
}

type tokenResponse struct {
	AccessToken  string    `json:"access_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token,omitempty"`
}

func newTokenResponse(p *auth.TokenPair) *tokenResponse {
	if p == nil {
		return nil
	}
	return &tokenResponse{AccessToken: p.AccessToken, ExpiresAt: p.AccessTokenExpiresAt, RefreshToken: p.RefreshToken}
}

// reply writes v, or maps err to an HTTP status without leaking details.
func reply(w http.ResponseWriter, r *http.Request, v any, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, v)
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	case errors.Is(err, passkey.ErrInvalidCeremony), errors.Is(err, passkey.ErrInvalidResponse):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "try_again"})
	case errors.Is(err, passkey.ErrCredentialExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_registered"})
	case errors.Is(err, auth.ErrUserNotFound):
		// For example, the account was deleted during registration.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_user"})
	case errors.Is(err, context.Canceled):
		// Client went away; nothing useful to send.
	default:
		slog.ErrorContext(r.Context(), "request failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
