# Migrating from v0.1

authgorm v0.1 implemented the callback options of auth v1. v0.2 implements the store interfaces of auth v2. The API is not compatible. Read auth's own [Migrating from v1](https://github.com/tpyle/auth/wiki/Migrating-from-v1) guide as well.

## Checklist

1. Upgrade both modules:
   ```bash
   go get github.com/tpyle/auth/v2@v2.1 github.com/tpyle/authgorm@v0.2
   ```
   and change `github.com/tpyle/auth` imports to `github.com/tpyle/auth/v2`. Go 1.26 or newer is required.
2. Replace the constructor and options (see the table below).
3. Check that `users` has no duplicate or `NULL` usernames (see [Users](#users)), then run `store.Migrate(ctx)`.
4. Drop the v0.1 `signing_keys` and `refresh_tokens` tables.
5. Expect every user to log in again: auth v2 rejects all tokens issued by v1.

## API mapping

| v0.1 | v0.2 |
|---|---|
| `authgorm.NewAuthGorm(db) *AuthGorm` | `authgorm.New(db) *Store` |
| `ag.Migrate() error` | `store.Migrate(ctx) error` |
| `auth.Create(ag.AsOptions(), ...)` | `auth.New(ctx, append(store.Options(), ...)...)` |
| `GetPasswordForUserSubject(subject)` | `LookupPasswordHash(ctx, username)`. Returns an error wrapping `auth.ErrUserNotFound` for unknown users instead of `gorm.ErrRecordNotFound`. |
| (none) | `UpdatePasswordHash(ctx, username, oldHash, newHash)`: compare-and-swap, used for automatic hash upgrades |
| (none) | `SetPasswordHash(ctx, username, hash)`: create or replace a user |
| `StoreNewSigningKey(kp)` | `StoreKey(ctx, key)` |
| `GetSigningKeyByID(id)` | `ListKeys(ctx)` (auth v2 caches the whole key set) |
| `DeleteSigningKeysByIDs(ids)` | `DeleteKeys(ctx, ids)`. Missing IDs are now ignored, as auth v2 requires. |
| `ErrNotAllKeysDeleted` | Removed |
| `StoreNewRefreshToken(rt)` | `CreateRefreshToken(ctx, rec)` |
| `GetRefreshTokenByID(id)` | `ConsumeRefreshToken(ctx, id, now)` |
| `DeleteRefreshTokenByID(id)` | `RevokeRefreshTokenFamily(ctx, familyID)` |
| (none) | `RevokeRefreshTokensForSubject(ctx, subject)` |
| (none) | `PurgeExpiredRefreshTokens(ctx, now)`, called by the `Authorizer` in the background |
| `SigningKey{gorm.Model, KeyID, PublicKey, CreationTime}` | `SigningKey{ID, PublicKey, CreatedAt, ExpiresAt}` in `auth_signing_keys` |
| `RefreshToken{gorm.Model, TokenID, UserID, User, Random}` | `RefreshToken{ID, ParentID, FamilyID, Subject, IssuedAt, ExpiresAt, UsedAt}` in `auth_refresh_tokens`, plus `RefreshFamily` and `RefreshSubject` |

Every method now takes a `context.Context` and passes it to GORM.

## Users

The `users` table keeps its name and columns, and v1 password hashes stay valid in auth v2. Users can log in with their existing passwords. Their hashes are upgraded to auth v2's default Argon2 parameters on their next login.

Two changes to the table:

- **`user_subject` gets a unique index.** v0.1's struct tag was malformed, so no unique constraint was ever created, and duplicate usernames were possible. `Migrate` fails if duplicates exist. Find them first:
  ```sql
  SELECT user_subject, COUNT(*) FROM users GROUP BY user_subject HAVING COUNT(*) > 1;
  ```
  Soft-deleted rows count too.
- **`user_subject` and `hashed_password` become `NOT NULL`.** The same malformed tag meant v0.1 never created this constraint either. Delete or fix rows with `NULL` in either column before migrating.
- **`user_subject` becomes a 255-character string** (needed to index it on MySQL). Usernames longer than that must be shortened before migrating.

## Signing keys and refresh tokens

auth v2 cannot use the v1 data. The v1 key IDs never matched the tokens they signed, and v1 refresh tokens carried a random secret that v2 does not have. v0.2 therefore uses new tables (`auth_signing_keys`, `auth_refresh_tokens`, `auth_refresh_families`, `auth_refresh_subjects`) and ignores the old ones. Once nothing runs v0.1 any more, drop them:

```go
err := db.Migrator().DropTable("refresh_tokens", "signing_keys")
```

Drop `refresh_tokens` first, because it has a foreign key to `users`.

## Rolling upgrade

v0.1 and v0.2 use different tables for keys and refresh tokens, so they can run against the same database at the same time. Tokens issued by one version are not accepted by the other, though. Upgrade every instance together, during a quiet period if possible.
