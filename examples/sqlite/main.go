// Command sqlite runs the whole auth flow (registration, login, token
// verification, refresh, reuse detection, logout and revoking every
// session) against a SQLite database file.
//
//	go run ./examples/sqlite [path/to/auth.db]
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/authgorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	path := filepath.Join(os.TempDir(), "authgorm-example.db")
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	if err := run(context.Background(), path); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, path string) error {
	// _txlock=immediate and a busy timeout make concurrent writers wait for
	// each other instead of failing with "database is locked".
	dsn := "file:" + path + "?_txlock=immediate&_busy_timeout=5000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
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

	// Registration: hash the password and store it.
	hash, err := a.HashPassword(ctx, []byte("correct horse battery staple"))
	if err != nil {
		return err
	}
	if err := store.SetPasswordHash(ctx, "alice", hash); err != nil {
		return err
	}

	if _, err := a.Login(ctx, "alice", []byte("wrong")); errors.Is(err, auth.ErrInvalidCredentials) {
		fmt.Println("wrong password rejected")
	}
	pair, err := a.Login(ctx, "alice", []byte("correct horse battery staple"))
	if err != nil {
		return err
	}
	claims, err := a.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil {
		return err
	}
	fmt.Println("logged in as", claims.Subject)

	// Refreshing rotates the refresh token. Using the old one again after
	// the grace window would revoke the session.
	newPair, err := a.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		return err
	}
	fmt.Println("refreshed; new access token expires", newPair.AccessTokenExpiresAt)

	if err := a.Logout(ctx, newPair.RefreshToken); err != nil {
		return err
	}
	if _, err := a.Refresh(ctx, newPair.RefreshToken); errors.Is(err, auth.ErrTokenRevoked) {
		fmt.Println("refresh after logout rejected")
	}

	// End every session, e.g. after a password change.
	if _, err := a.Login(ctx, "alice", []byte("correct horse battery staple")); err != nil {
		return err
	}
	if err := a.RevokeAllSessions(ctx, "alice"); err != nil {
		return err
	}
	fmt.Println("all sessions revoked")
	fmt.Println("database:", path)
	return nil
}
