package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/authgorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newServer serves routes backed by SQLite, so the handlers can be tested
// without PostgreSQL.
func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "auth.db") + "?_txlock=immediate&_busy_timeout=5000"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	store := authgorm.New(db)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	cheap := auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	a, err := auth.New(ctx, append(store.Options(), auth.WithArgon2Params(cheap))...)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(routes(a, store))
	t.Cleanup(func() {
		srv.Close()
		_ = a.Close()
	})
	return srv
}

func post(t *testing.T, srv *httptest.Server, path, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodePair(t *testing.T, resp *http.Response) auth.TokenPair {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var p auth.TokenPair
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoutes(t *testing.T) {
	srv := newServer(t)

	if resp := post(t, srv, "/register", `{"username":""}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty register: status = %d, want 400", resp.StatusCode)
	}
	if resp := post(t, srv, "/register", `{"username":"alice","password":"pw"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want 201", resp.StatusCode)
	}
	// Registering a taken username must not replace its password.
	if resp := post(t, srv, "/register", `{"username":"alice","password":"stolen"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate register: status = %d, want 409", resp.StatusCode)
	}
	if resp := post(t, srv, "/login", `{"username":"alice","password":"stolen"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("login with the second password: status = %d, want 401", resp.StatusCode)
	}
	if resp := post(t, srv, "/login", `{"username":"alice","password":"nope"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad login: status = %d, want 401", resp.StatusCode)
	}
	if resp := post(t, srv, "/login", `not json`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed login: status = %d, want 400", resp.StatusCode)
	}
	pair := decodePair(t, post(t, srv, "/login", `{"username":"alice","password":"pw"}`))

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/me", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var me map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil || me["subject"] != "alice" {
		t.Errorf("/me = %v, %v; want subject alice", me, err)
	}

	pair = decodePair(t, post(t, srv, "/refresh", `{"refresh_token":"`+pair.RefreshToken+`"}`))
	if resp := post(t, srv, "/logout", `{"refresh_token":"`+pair.RefreshToken+`"}`); resp.StatusCode != http.StatusNoContent {
		t.Errorf("logout: status = %d, want 204", resp.StatusCode)
	}
	if resp := post(t, srv, "/refresh", `{"refresh_token":"`+pair.RefreshToken+`"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("refresh after logout: status = %d, want 401", resp.StatusCode)
	}

	jwks, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jwks.Body.Close() }()
	if jwks.StatusCode != http.StatusOK {
		t.Errorf("jwks: status = %d, want 200", jwks.StatusCode)
	}
}
