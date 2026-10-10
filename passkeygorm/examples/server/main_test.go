package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"uuid"

	"github.com/tpyle/auth/v2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newTestApp(t *testing.T) *app {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "app.db") + "?_txlock=immediate&_busy_timeout=5000"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	cheap := auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	a, err := newApp(ctx, db, origin, auth.WithArgon2Params(cheap))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.auth.Close() })
	// Seeding twice must not replace the password.
	for range 2 {
		if err := a.seed(ctx, "alice", "password"); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func TestServerRoutes(t *testing.T) {
	srv := httptest.NewServer(newTestApp(t).routes())
	defer srv.Close()

	do := func(method, path, body, token string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("GET / = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	if code, _ := do("POST", "/passkey/register/begin", "", ""); code != http.StatusUnauthorized {
		t.Errorf("register without token = %d", code)
	}
	if code, _ := do("POST", "/login", `{"username":"alice","password":"wrong"}`, ""); code != http.StatusUnauthorized {
		t.Errorf("login with wrong password = %d", code)
	}
	code, login := do("POST", "/login", `{"username":"alice","password":"password"}`, "")
	if code != http.StatusOK {
		t.Fatalf("login = %d", code)
	}
	token := login["access_token"].(string)
	if code, me := do("GET", "/me", "", token); code != http.StatusOK || me["subject"] != "alice" {
		t.Errorf("/me = %d %v", code, me)
	}

	code, ch := do("POST", "/passkey/register/begin", "", token)
	if code != http.StatusOK || ch["ceremonyId"] == nil || ch["options"] == nil {
		t.Fatalf("register begin = %d %v", code, ch)
	}
	body := `{"ceremonyId":"` + ch["ceremonyId"].(string) + `","credential":{"id":"x"}}`
	if code, _ := do("POST", "/passkey/register/finish", body, token); code != http.StatusBadRequest {
		t.Errorf("register finish with bad credential = %d", code)
	}
	if code, list := do("GET", "/passkeys", "", token); code != http.StatusOK || list != nil {
		t.Errorf("list = %d %v", code, list)
	}

	code, ch = do("POST", "/passkey/login/begin", "", "")
	if code != http.StatusOK {
		t.Fatalf("login begin = %d", code)
	}
	body = `{"ceremonyId":"` + ch["ceremonyId"].(string) + `","credential":{"id":"x"}}`
	if code, _ := do("POST", "/passkey/login/finish", body, ""); code != http.StatusUnauthorized {
		t.Errorf("login finish with bad credential = %d", code)
	}
	body = `{"ceremonyId":"` + uuid.New().String() + `","credential":{}}`
	if code, _ := do("POST", "/passkey/login/finish", body, ""); code != http.StatusBadRequest {
		t.Errorf("login finish with unknown ceremony = %d", code)
	}
	if code, _ := do("POST", "/passkey/login/finish", "not json", ""); code != http.StatusBadRequest {
		t.Errorf("login finish with bad JSON = %d", code)
	}
}
