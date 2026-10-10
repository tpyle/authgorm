// Package passkeygorm stores the state of a [github.com/tpyle/auth/passkey]
// service in any database supported by GORM.
//
// A single [Store] implements the three passkey store interfaces:
// [passkey.UserStore], [passkey.CredentialStore] and
// [passkey.CeremonyStore]. Create one with [New], create its tables with
// [Store.Migrate], and pass it to [passkey.New] with [Store.Options]:
//
//	store := passkeygorm.New(db)
//	if err := store.Migrate(ctx); err != nil {
//		return err
//	}
//	pk, err := passkey.New(append(store.Options(),
//		passkey.WithRelyingParty("example.com", "Example", "https://example.com"),
//		passkey.WithTokenIssuer(authorizer),
//	)...)
//
// It is a separate module from [github.com/tpyle/authgorm], because the
// passkey module requires Go 1.27 and a WebAuthn library. Use the two
// together to keep both password and passkey state in one database.
//
// # Users
//
// WebAuthn identifies each user by a random, permanent "user handle". The
// store keeps handles in their own table, keyed by subject (the username used
// by the auth package), so users do not need a password to have passkeys.
// Call [Store.EnsureUser] before a user's first passkey registration, for
// example at sign-up or just before [passkey.Passkeys.BeginRegistration].
//
// # Tables
//
// [User], [Credential] and [Ceremony] are stored in tables prefixed with
// "auth_passkey_".
//
// # Concurrency
//
// The store is safe for concurrent use and needs no locks or transactions
// beyond single statements: credential uses are recorded with an UPDATE that
// only ever raises the signature counter, and a ceremony is consumed by
// whichever caller's DELETE removes it. For SQLite, open the database with
// "_txlock=immediate" and a busy timeout, as for authgorm.
//
// # Maintenance
//
// Expired ceremonies are deleted by [Store.SaveCeremony], at most once a
// minute per Store (see [WithCeremonyPurgeInterval]), so abandoned
// ceremonies do not accumulate. [Store.PurgeExpiredCeremonies] purges on
// demand.
package passkeygorm
