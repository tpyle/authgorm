# Getting Started

## Install

```bash
go get github.com/tpyle/authgorm github.com/tpyle/auth/v2
```

authgorm requires auth v2.1.0 or newer. You also need a GORM driver, for example `gorm.io/driver/postgres` or `gorm.io/driver/sqlite`. authgorm requires Go 1.26 or newer, the same as auth v2. For passkeys, see [Passkeys](Passkeys.md).

## Connect and migrate

```go
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
if err != nil {
	return err
}
store := authgorm.New(db)
if err := store.Migrate(ctx); err != nil {
	return err
}
```

`Migrate` runs GORM's `AutoMigrate` for every table in the [Schema](Schema.md). It is safe to run on every start. If you manage your schema with a migration tool instead, create the same tables and indexes by hand.

Give every `gorm.Open` call its own `*gorm.Config`. See [Databases and Concurrency](Databases-and-Concurrency.md#do-not-share-a-gormconfig) for why.

## Create the Authorizer

`Store.Options()` returns `auth.WithUserStore`, `auth.WithKeyStore` and `auth.WithRefreshTokenStore`, all pointing at the store. Append any other options:

```go
a, err := auth.New(ctx, append(store.Options(),
	auth.WithIssuer("my-service"),
	auth.WithAccessTokenTTL(10*time.Minute),
)...)
if err != nil {
	return err
}
defer a.Close()
```

If you only want some of the stores in the database, pass them individually instead, for example `auth.WithKeyStore(store)` alone.

## Register users

The store reads users but leaves registration to you. `SetPasswordHash` creates a user, or replaces the hash of an existing one:

```go
hash, err := a.HashPassword(ctx, []byte(password))
if err != nil {
	return err
}
if err := store.SetPasswordHash(ctx, username, hash); err != nil {
	return err
}
```

`SetPasswordHash` does not check whether the user already exists, so a sign-up handler should check first (for example by calling `LookupPasswordHash` and expecting `auth.ErrUserNotFound`) to avoid overwriting someone's password. The unique index on the username stops two concurrent sign-ups from creating duplicates: the second one fails.

The `User` model is exported, so you can work with the table through GORM directly, for example to add your own columns in a separate table keyed by `User.ID`, or to delete users. `User` embeds `gorm.Model`, so `db.Delete` is a soft delete: the user can no longer log in, but the username stays taken until the row is removed with `db.Unscoped().Delete`.

When a user logs in with a hash whose Argon2 parameters are out of date, the `Authorizer` calls `UpdatePasswordHash` to store a new one. The store updates the row only if it still holds the hash that was verified, so a concurrent password change is never undone.

## Log in, refresh, log out

Everything else goes through the `Authorizer`. See the [auth wiki](https://github.com/tpyle/auth/wiki/Getting-Started):

```go
pair, err := a.Login(ctx, username, []byte(password))
claims, err := a.VerifyAccessToken(ctx, pair.AccessToken)
pair, err = a.Refresh(ctx, pair.RefreshToken)
err = a.Logout(ctx, pair.RefreshToken)
err = a.RevokeAllSessions(ctx, username)
```

## Expired refresh tokens

`Store` implements auth's optional `RefreshTokenPurger` interface, so every `Authorizer` that uses it deletes expired refresh tokens and sessions in the background. This happens about every `RefreshPurgeInterval` (default one hour, randomized by ±25% so instances don't purge in lockstep). The `Authorizer` keeps records for 5 minutes past their expiry, so a refresh accepted just before expiry still completes. Running several instances against one database is safe: each purge deletes in batches of 1000 rows, and concurrent purges don't conflict.

To purge on your own schedule instead, for example from a cron job, disable the background purge and call the `Authorizer`:

```go
a, err := auth.New(ctx, append(store.Options(), auth.WithRefreshPurgeInterval(0))...)
// later, from your job:
n, err := a.PurgeExpiredRefreshTokens(ctx)
```

Expired signing keys need no maintenance: each `Authorizer` deletes them itself.
