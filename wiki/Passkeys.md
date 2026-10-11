# Passkeys

`github.com/tpyle/authgorm/passkeygorm` stores the state of a [`github.com/tpyle/auth/passkey`](https://github.com/tpyle/auth/wiki/Passkeys) service (passwordless login with passkeys and FIDO2 security keys) in any database GORM supports. One `passkeygorm.Store` implements all three passkey store interfaces:

| passkey interface | What it stores | Table |
|---|---|---|
| `UserStore` | Each user's WebAuthn user handle and names | `auth_passkey_users` |
| `CredentialStore` | Registered public keys | `auth_passkey_credentials` |
| `CeremonyStore` | Challenges between the Begin and Finish steps | `auth_passkey_ceremonies` |

It's a **separate Go module** from authgorm, just as the passkey package is separate from auth. The passkey module requires **Go 1.27** (it uses the standard library's `uuid` package) and pulls in a WebAuthn library, and services without passkeys shouldn't need either.

```bash
go get github.com/tpyle/authgorm/passkeygorm
```

## Setup

Use it alongside authgorm, on the same database. authgorm handles passwords, signing keys and sessions, and passkeygorm handles passkeys. A passkey login issues tokens through the same `Authorizer`, so the resulting sessions live in authgorm's tables.

```go
core := authgorm.New(db)
passkeys := passkeygorm.New(db)
if err := core.Migrate(ctx); err != nil { ... }
if err := passkeys.Migrate(ctx); err != nil { ... }

a, err := auth.New(ctx, core.Options()...)

pk, err := passkey.New(append(passkeys.Options(),
	passkey.WithRelyingParty("example.com", "Example Corp", "https://example.com"),
	passkey.WithTokenIssuer(a),
)...)
```

`Store.Options()` returns `passkey.WithUserStore`, `passkey.WithCredentialStore` and `passkey.WithCeremonyStore`, all pointing at the store. Because ceremonies are in the database, a ceremony begun on one instance can be finished on any other.

## Users and handles

WebAuthn identifies a user by a **user handle**: random bytes stored on the authenticator and returned at login. A handle must never change, so passkeygorm keeps handles in their own table, keyed by subject (the username the auth package uses), rather than in authgorm's `users` table. Users therefore don't need a password to have passkeys.

Give a user an identity before their first passkey registration:

```go
// Safe to call before every registration: an existing user is returned unchanged.
if _, err := passkeys.EnsureUser(ctx, subject, email, displayName); err != nil { ... }
ch, err := pk.BeginRegistration(ctx, subject)
```

- `name` (here `email`) is what authenticators show when the user picks a passkey. Empty means the subject.
- `displayName` is a friendlier name. Empty means `name`.
- Concurrent calls for the same subject all get the same handle.
- To change the names later, update the `passkeygorm.User` row with GORM. Passkeys already on authenticators keep showing the old names until they're registered again.

`BeginRegistration` returns `auth.ErrUserNotFound` for a subject without an identity.

**Deleting an account:** call `passkeys.DeleteUser(ctx, subject)`. It deletes the identity and every credential registered to it, including one from a registration that finishes at the same time. Also delete the user's `authgorm.User` row if there is one, then call `a.RevokeAllSessions(ctx, subject)`. Revoke last, so a login that happens during the deletion can't create a session after the revocation.

**Signing up with only a passkey:** call `EnsureUser`, issue a session with `a.IssueTokenPair(ctx, subject, nil)`, then run registration with that token. No `authgorm.User` row is needed.

## Schema

### auth_passkey_users (`User`)

| Column | Type | Notes |
|---|---|---|
| `subject` | string(255), primary key | The username. |
| `handle` | bytes(64), unique | The WebAuthn user handle (32 random bytes). |
| `name` | string | Account name shown by authenticators. |
| `display_name` | string | Friendlier name. Empty means `name`. |
| `created_at` | time | |

### auth_passkey_credentials (`Credential`)

| Column | Type | Notes |
|---|---|---|
| `id` | bytes(1023), primary key | Credential ID chosen by the authenticator, unique across all users. |
| `subject` | string(255), indexed | The owner. |
| `public_key` | bytes | COSE-encoded public key. |
| `sign_count` | int64 | Highest signature counter seen (a uint32). |
| `aaguid` | bytes(16) | Authenticator model. |
| `transports` | text (JSON array) | Such as `["internal","hybrid"]`. |
| `attestation_type`, `attestation_format` | string | As reported at registration. |
| `user_verified`, `backup_eligible`, `backup_state` | bool | |
| `clone_warning` | bool | Set when the counter went backwards. Never cleared by the store. |
| `label` | string | User-facing name, such as "Work laptop". |
| `created_at` | time | |
| `last_used_at` | time, nullable | `NULL` means never used. |

### auth_passkey_ceremonies (`Ceremony`)

| Column | Type | Notes |
|---|---|---|
| `id` | string(36), primary key | Ceremony UUID. |
| `data` | bytes | Opaque state (a few hundred bytes, no secrets). |
| `expires_at` | time, indexed | |

## How the contracts are met

The passkey package requires some operations to be atomic. passkeygorm does most of them with a single statement. Only saving a credential and deleting a user use a short transaction with a row lock:

| Requirement | Statement |
|---|---|
| A credential ID is unique across users (`ErrCredentialExists`) | `INSERT ... ON CONFLICT DO NOTHING`. If no row was inserted, the ID exists. |
| A credential is never saved for a deleted user | `CreateCredential` locks the user's row (`SELECT ... FOR UPDATE`) before inserting, and `DeleteUser` deletes the user row before the credentials, in one transaction. Either the delete waits and then removes the new credential, or the registration waits and fails with `auth.ErrUserNotFound`. Otherwise a later user given the same subject could inherit the credential. |
| The signature counter never decreases; `UserVerified` and `CloneWarning` never clear | `UPDATE ... SET sign_count = CASE WHEN sign_count < ? THEN ? ELSE sign_count END, user_verified = user_verified OR ?, clone_warning = clone_warning OR ?`. `last_used_at` is only set when the use has a time. |
| Only the owner can delete a credential (`ErrCredentialNotFound`) | `DELETE ... WHERE id = ? AND subject = ?`. If no row was deleted, the credential wasn't the user's. |
| A ceremony finishes at most once | Read the row, then `DELETE` it by ID. Only the caller whose delete removes the row gets the data. |

These statements behave the same on PostgreSQL, SQLite and MySQL. SQLite has no row locks, but with `_txlock=immediate` its transactions run one at a time, which gives the same result. The tests run every contract, including concurrent ceremony consumption, racing counter updates and registrations racing account deletion, against SQLite and PostgreSQL. For SQLite, use the connection options from [Databases and Concurrency](Databases-and-Concurrency.md#sqlite).

## Expired ceremonies

Every Begin call stores a ceremony that lives for `CeremonyTTL` (default 5 minutes). Abandoned ones are deleted automatically: at most once a minute per `Store`, `SaveCeremony` first deletes up to 1000 expired ceremonies. If it deleted a full batch, the next call deletes another one straight away, so a backlog clears quickly without slowing any single request much. The cleanup isn't stopped if the request is cancelled, but gives up after 5 seconds. A failed cleanup never fails the Begin, and is retried after the interval.

Options:

```go
passkeygorm.New(db,
	passkeygorm.WithCeremonyPurgeInterval(5*time.Minute), // 0 disables the automatic cleanup
	passkeygorm.WithClock(clock.Now),                     // pass the same clock as passkey.WithClock
)
```

With the automatic cleanup disabled, call `store.PurgeExpiredCeremonies(ctx, time.Now())` yourself. It deletes every expired ceremony, in batches of 1000.

`BeginLogin` needs no authentication, so **rate-limit the Begin endpoints**. Otherwise anonymous clients can fill the ceremony table faster than it's cleaned.

## Example

[`passkeygorm/examples/server`](../passkeygorm/examples/server/main.go) is a browser app with password login, passkey registration and passwordless login, all stored in one SQLite file:

```bash
cd passkeygorm && go run ./examples/server
```

Open http://localhost:8080 and sign in with `alice` / `password`. Register a passkey, sign out, restart the server, and sign back in with the passkey.
