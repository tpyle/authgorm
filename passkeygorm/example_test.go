package passkeygorm_test

import (
	"context"
	"fmt"
	"log"

	"github.com/tpyle/auth/passkey"
	"github.com/tpyle/auth/v2"
	"github.com/tpyle/authgorm"
	"github.com/tpyle/authgorm/passkeygorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Example wires authgorm and passkeygorm to one database, so passwords,
// sessions and passkeys share it.
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

	core := authgorm.New(db)
	passkeys := passkeygorm.New(db)
	for _, migrate := range []func(context.Context) error{core.Migrate, passkeys.Migrate} {
		if err := migrate(ctx); err != nil {
			log.Fatal(err)
		}
	}

	a, err := auth.New(ctx, core.Options()...)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	pk, err := passkey.New(append(passkeys.Options(),
		passkey.WithRelyingParty("example.com", "Example", "https://example.com"),
		passkey.WithTokenIssuer(a),
	)...)
	if err != nil {
		log.Fatal(err)
	}

	// Give alice a WebAuthn identity, then start adding a passkey. The
	// options go to navigator.credentials.create in the browser.
	if _, err := passkeys.EnsureUser(ctx, "alice", "alice@example.com", "Alice"); err != nil {
		log.Fatal(err)
	}
	ch, err := pk.BeginRegistration(ctx, "alice")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("registration options ready:", len(ch.Options) > 0)
	// Output:
	// registration options ready: true
}
