# Databases and Concurrency

The auth package requires its stores to be safe for concurrent use, and some refresh-token operations to be atomic with respect to each other. See [Storage](https://github.com/tpyle/auth/wiki/Storage) in the auth wiki. This page explains how authgorm meets those rules and what each database needs.

## What has to be atomic

1. **Consuming a refresh token.** Of any number of concurrent `Refresh` calls with the same token, exactly one may see it as unused. Otherwise one stolen token could be refreshed twice without triggering reuse detection.
2. **Refresh vs. revoke.** A refresh that races a logout must either be rejected, or have its new token deleted by the logout.
3. **Login vs. revoke-all.** A login that races `RevokeAllSessions` must either be revoked by it, or happen entirely after it.

## How the store does it

| Operation | Mechanism |
|---|---|
| `ConsumeRefreshToken` | Reads the record, then runs `UPDATE ... SET used_at = ? WHERE id = ? AND used_at IS NULL`. Only the caller whose update changes a row has consumed the token. Everyone else reads the record again and gets the winner's `used_at`. |
| `CreateRefreshToken`, refresh | In a transaction: `SELECT ... FOR UPDATE` on the family row, reject if missing or revoked, extend `expires_at`, insert the token. |
| `CreateRefreshToken`, login | In a transaction: upsert the user's `auth_refresh_subjects` row (which locks it), insert the family, insert the token. |
| `RevokeRefreshTokenFamily` | In a transaction: `UPDATE` the family row to `revoked = true`, which waits for any refresh holding it, then delete its tokens. |
| `RevokeRefreshTokensForSubject` | In a transaction: upsert the subject row, which waits for any login in progress, then mark the subject's families revoked and delete their tokens. |

Locks are always taken in the same order (subject row, then family row), so these operations cannot deadlock each other.

The test suite runs every scenario above concurrently against SQLite and, when configured, PostgreSQL.

## PostgreSQL

Supported and tested. Use the default `READ COMMITTED` isolation level. Under `REPEATABLE READ` or `SERIALIZABLE`, racing operations fail with serialization errors, which `Refresh` reports as internal errors, instead of waiting for each other.

## MySQL / MariaDB

Expected to work with InnoDB at the default `REPEATABLE READ` level: `SELECT ... FOR UPDATE`, `UPDATE` and `DELETE` all read the latest committed rows and take row locks, and `INSERT ... ON DUPLICATE KEY UPDATE` locks the subject row. It is not covered by the automated tests.

GORM's MySQL driver stores `time.Time` with millisecond precision by default. That is fine for every timestamp the store uses.

## SQLite

Supported and tested. SQLite has no row locks (GORM's SQLite driver drops `FOR UPDATE`), but it allows only one writer at a time, which gives the same guarantees. Open the database with:

```go
dsn := "file:auth.db?_txlock=immediate&_busy_timeout=5000&_journal_mode=WAL"
```

- `_txlock=immediate` makes each transaction take the write lock when it starts. With the default deferred transactions, two transactions that both read and then write can fail with `database is locked` instead of waiting.
- `_busy_timeout` makes waiting writers retry for up to that many milliseconds.
- `_journal_mode=WAL` lets readers continue while a write is in progress.

With these options, every write is serialized. That is plenty for a single-instance service. A SQLite file cannot be shared by several hosts, so for several instances use a server database.

For `:memory:` databases, call `sqlDB.SetMaxOpenConns(1)`, because every connection to `:memory:` opens a separate, empty database.

## Other databases

SQL Server and others supported by GORM probably work for single-instance use. Whether their upsert (`MERGE`) and `FOR UPDATE` translations take the locks described above has not been verified.

## Do not share a gorm.Config

Give each `gorm.Open` call its own `&gorm.Config{}`. `gorm.Open` stores the dialect's clause builders in the config it is given, so one config shared between, say, a SQLite and a PostgreSQL connection makes the PostgreSQL connection use SQLite's builders. SQLite's builder removes `FOR UPDATE`. The PostgreSQL store would then lose the refresh-vs-revoke guarantee, and nothing would report an error.
