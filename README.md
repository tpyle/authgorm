# authgorm

GORM-backed storage for [`github.com/tpyle/auth/v2`](https://github.com/tpyle/auth). One `authgorm.Store` implements every store the auth package uses (`UserStore`, `PasswordHashUpdater`, `KeyStore` and `RefreshTokenStore`) on any database GORM supports. Tokens issued by one instance of your service then verify on every other instance, and sessions survive restarts.

## Installation

```bash
go get github.com/tpyle/authgorm github.com/tpyle/auth/v2
```

Requires Go 1.26 or newer and auth v2.1.0 or newer.

## Quick start

```go
package main

import (
	"context"
	"log"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/authgorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	ctx := context.Background()
	db, err := gorm.Open(postgres.Open("host=localhost user=postgres dbname=app"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	store := authgorm.New(db)
	if err := store.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	a, err := auth.New(ctx, append(store.Options(), auth.WithIssuer("my-service"))...)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	// Register a user.
	hash, err := a.HashPassword(ctx, []byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	if err := store.SetPasswordHash(ctx, "alice", hash); err != nil {
		log.Fatal(err)
	}

	// Log in.
	pair, err := a.Login(ctx, "alice", []byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	_ = pair
}
```

`Store` also implements auth's `RefreshTokenPurger`, so the `Authorizer` deletes expired refresh tokens in the background. No scheduled job is needed.

## Passkeys

The [`passkeygorm`](passkeygorm/) module does the same for [`github.com/tpyle/auth/passkey`](https://github.com/tpyle/auth/wiki/Passkeys): one `passkeygorm.Store` keeps passkey users, credentials and ceremonies in the same database.

```go
passkeys := passkeygorm.New(db)
if err := passkeys.Migrate(ctx); err != nil {
	log.Fatal(err)
}
pk, err := passkey.New(append(passkeys.Options(),
	passkey.WithRelyingParty("example.com", "Example", "https://example.com"),
	passkey.WithTokenIssuer(a),
)...)
```

It's a separate module (`go get github.com/tpyle/authgorm/passkeygorm`), because the passkey package needs Go 1.27 and a WebAuthn library. See [Passkeys](wiki/Passkeys.md).

## Tables

| Table | Contents |
|---|---|
| `users` | Usernames and Argon2id password hashes (unchanged from v0.1) |
| `auth_signing_keys` | Public halves of signing keys |
| `auth_refresh_families` | One row per login session, including revoked ones until they expire |
| `auth_refresh_tokens` | One row per refresh token |
| `auth_refresh_subjects` | Per-user lock rows that make logins atomic with "revoke all sessions" |

## Databases

PostgreSQL and SQLite are tested, including concurrent refresh, logout and revoke races. MySQL is expected to work. For SQLite, open the database with `_txlock=immediate` and a busy timeout. See [Databases and Concurrency](wiki/Databases-and-Concurrency.md).

## Documentation

- [Wiki](wiki/Home.md): [Getting Started](wiki/Getting-Started.md), [Schema](wiki/Schema.md), [Databases and Concurrency](wiki/Databases-and-Concurrency.md), [Passkeys](wiki/Passkeys.md), [Migrating from v0.1](wiki/Migrating-from-v0.1.md)
- [Examples](examples/): a SQLite walkthrough and a multi-instance PostgreSQL HTTP API, plus a browser passkey demo in [`passkeygorm/examples/server`](passkeygorm/examples/server/)
- API reference: `go doc github.com/tpyle/authgorm`

## Testing

```bash
go test ./...
(cd passkeygorm && go test ./...)
```

The repository holds two Go modules, so test each one. The tests use SQLite. To run them against PostgreSQL as well, point `AUTHGORM_TEST_POSTGRES_DSN` at a database the tests may drop tables in:

```bash
export AUTHGORM_TEST_POSTGRES_DSN="host=localhost user=postgres password=postgres dbname=authgorm_test sslmode=disable"
go test -race ./... && (cd passkeygorm && go test -race ./...)
```

## License

See [LICENSE](LICENSE).
