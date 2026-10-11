# authgorm

`github.com/tpyle/authgorm` stores the state of a [`github.com/tpyle/auth/v2`](https://github.com/tpyle/auth) `Authorizer` in any database GORM supports. One `authgorm.Store` implements every store interface the auth package uses:

| auth interface | What it stores | Table |
|---|---|---|
| `UserStore` | Password hashes | `users` |
| `PasswordHashUpdater` | Upgraded hashes, compare-and-swap | `users` |
| `KeyStore` | Public halves of signing keys | `auth_signing_keys` |
| `RefreshTokenStore`, `RefreshTokenPurger` | Refresh-token records and sessions ("families"), purged automatically | `auth_refresh_tokens`, `auth_refresh_families`, `auth_refresh_subjects` |

```go
store := authgorm.New(db)
if err := store.Migrate(ctx); err != nil { ... }
a, err := auth.New(ctx, store.Options()...)
```

Because keys and refresh-token state live in the database, every instance of a service that shares it can verify the others' tokens, and sessions survive restarts.

## Pages

| Page | Contents |
|---|---|
| [Getting Started](Getting-Started.md) | Install, connect, migrate, register users, wire up the `Authorizer`, expired tokens |
| [Schema](Schema.md) | Every table and column, and what the store does with them |
| [Databases and Concurrency](Databases-and-Concurrency.md) | How the store meets the auth package's atomicity rules, and per-database setup (PostgreSQL, MySQL, SQLite) |
| [Passkeys](Passkeys.md) | The `passkeygorm` module: passkey users, credentials and ceremonies for `github.com/tpyle/auth/passkey` |
| [Migrating from v0.1](Migrating-from-v0.1.md) | Upgrading from authgorm v0.1 (auth v1) |

## Examples

- [`examples/sqlite`](../examples/sqlite/main.go): the whole flow against a SQLite file.
- [`examples/postgres`](../examples/postgres/main.go): an HTTP API on PostgreSQL that can run as several instances.
- [`passkeygorm/examples/server`](../passkeygorm/examples/server/main.go): password and passkey login in a browser, all state in SQLite.

Passkey support (`github.com/tpyle/auth/passkey`) lives in the separate [`passkeygorm`](Passkeys.md) module, so services without passkeys don't need Go 1.27 or a WebAuthn library.
