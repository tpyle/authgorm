package authgorm_test

import (
	"context"
	"fmt"
	"log"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/authgorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Example() {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		log.Fatal(err)
	}
	// Each connection to ":memory:" is a separate database.
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)

	store := authgorm.New(db)
	if err := store.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	a, err := auth.New(ctx, store.Options()...)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	// Registration.
	hash, err := a.HashPassword(ctx, []byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	if err := store.SetPasswordHash(ctx, "alice", hash); err != nil {
		log.Fatal(err)
	}

	// Login, verification and refresh.
	pair, err := a.Login(ctx, "alice", []byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	claims, err := a.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("logged in as", claims.Subject)

	pair, err = a.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}
	if err := a.Logout(ctx, pair.RefreshToken); err != nil {
		log.Fatal(err)
	}
	fmt.Println("logged out")
	// Output:
	// logged in as alice
	// logged out
}
