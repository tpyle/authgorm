// Package authgorm stores the state of a [github.com/tpyle/auth/v2]
// Authorizer in any database supported by GORM.
//
// A single [Store] implements every store interface the auth package uses:
// [auth.UserStore], [auth.PasswordHashUpdater], [auth.KeyStore] and
// [auth.RefreshTokenStore]. Create one with [New], create its tables with
// [Store.Migrate], and pass it to [auth.New] with [Store.Options]:
//
//	store := authgorm.New(db)
//	if err := store.Migrate(ctx); err != nil {
//		return err
//	}
//	a, err := auth.New(ctx, store.Options()...)
//
// # Tables
//
// Users live in the "users" table ([User]). Signing keys and refresh-token
// state live in tables prefixed with "auth_": [SigningKey], [RefreshFamily],
// [RefreshToken] and [RefreshSubject].
//
// # Concurrency
//
// The refresh-token methods must be atomic with respect to each other (see
// [auth.RefreshTokenStore]). Store gets this from row locks: SELECT ... FOR
// UPDATE on a token family, and an upsert on a per-subject row in
// [RefreshSubject]. This is correct on PostgreSQL and MySQL at their default
// isolation levels, and on SQLite, where writers are serialized. For SQLite,
// open the database with "_txlock=immediate" and a busy timeout so that
// concurrent writers wait instead of failing with "database is locked".
//
// # Maintenance
//
// Store implements [auth.RefreshTokenPurger], so every Authorizer that uses
// it deletes expired refresh tokens and sessions in the background, every
// auth.Config.RefreshPurgeInterval (default one hour). Expired signing keys
// are likewise deleted by the Authorizer. No scheduled job is needed.
package authgorm
