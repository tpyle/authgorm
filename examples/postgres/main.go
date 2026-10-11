// Command postgres serves a small HTTP API backed by PostgreSQL. Run several
// copies against the same database: tokens issued by one are accepted by the
// others, because they share signing keys and refresh-token state. Each
// instance purges expired refresh tokens in the background.
//
//	DATABASE_URL="host=localhost user=postgres password=postgres dbname=app sslmode=disable" \
//	ADDR=:8080 go run ./examples/postgres
//
// Endpoints:
//
//	POST /register {"username": "...", "password": "..."}
//	POST /login    {"username": "...", "password": "..."}  -> token pair
//	POST /refresh  {"refresh_token": "..."}                 -> token pair
//	POST /logout   {"refresh_token": "..."}
//	GET  /me       (Authorization: Bearer <access token>)
//	GET  /.well-known/jwks.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
	"unicode/utf8"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/authgorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Getenv("DATABASE_URL"), envOr("ADDR", ":8080")); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, dsn, addr string) error {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}
	store := authgorm.New(db)
	if err := store.Migrate(ctx); err != nil {
		return err
	}
	a, err := auth.New(ctx, append(store.Options(), auth.WithIssuer("authgorm-example"))...)
	if err != nil {
		return err
	}
	defer func() { _ = a.Close() }()

	srv := &http.Server{Addr: addr, Handler: routes(a, store), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("listening on %s", addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// maxUsernameLength is the length of authgorm's user_subject column.
const maxUsernameLength = 255

// decode reads a JSON request body of at most 64 KiB into v.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	return json.NewDecoder(r.Body).Decode(v)
}

func routes(a *auth.Authorizer, store *authgorm.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		var c credentials
		if err := decode(w, r, &c); err != nil || c.Username == "" || c.Password == "" {
			http.Error(w, "username and password required", http.StatusBadRequest)
			return
		}
		// Checked before the expensive hash, and because the column holds
		// at most 255 characters.
		if utf8.RuneCountInString(c.Username) > maxUsernameLength {
			http.Error(w, "username too long", http.StatusBadRequest)
			return
		}
		hash, err := a.HashPassword(r.Context(), []byte(c.Password))
		if err != nil {
			writeError(w, err)
			return
		}
		if err := store.CreateUser(r.Context(), c.Username, hash); err != nil {
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var c credentials
		if err := decode(w, r, &c); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pair, err := a.Login(r.Context(), c.Username, []byte(c.Password))
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, pair)
	})
	mux.HandleFunc("POST /refresh", func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if err := decode(w, r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pair, err := a.Refresh(r.Context(), req.RefreshToken)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, pair)
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if err := decode(w, r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := a.Logout(r.Context(), req.RefreshToken); err != nil {
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("GET /me", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		writeJSON(w, map[string]string{"subject": subject})
	})))
	mux.Handle("GET /.well-known/jwks.json", a.JWKSHandler())
	return mux
}

// writeError maps auth errors to HTTP statuses.
func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrInvalidToken),
		errors.Is(err, auth.ErrTokenExpired),
		errors.Is(err, auth.ErrTokenRevoked),
		errors.Is(err, auth.ErrRefreshTokenReused):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, authgorm.ErrUserExists):
		http.Error(w, "username taken", http.StatusConflict)
	default:
		log.Printf("internal error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writing response: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
