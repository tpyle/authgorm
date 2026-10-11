# Schema

`Store.Migrate` creates these tables with GORM's `AutoMigrate`. Each one has an exported model type, so you can query it with GORM. UUIDs are stored as 36-character strings, and times are stored in UTC.

## users (`User`)

| Column | Type | Notes |
|---|---|---|
| `id`, `created_at`, `updated_at`, `deleted_at` | | From `gorm.Model`. Users with `deleted_at` set are invisible to the store. |
| `user_subject` | string(255), unique | The username passed to `Login`/`Authenticate`, and the `sub` claim of issued tokens. |
| `hashed_password` | string | PHC-encoded Argon2id hash (`$argon2id$v=19$m=...`). |

The table name and columns are the same as in authgorm v0.1, so existing users carry over.

## auth_signing_keys (`SigningKey`)

| Column | Type | Notes |
|---|---|---|
| `id` | string(36), primary key | The key's UUID, which is the `kid` header of the tokens it signs. |
| `public_key` | bytes | PKIX DER encoding of the P-256 public key. Private keys are never stored. |
| `created_at` | time | When the key was generated. |
| `expires_at` | time, nullable | When no token signed by the key can still be valid. `NULL` means never (key rotation disabled). |

Every instance stores its own keys here and reads everyone else's, which is how tokens issued by one instance verify on another. Each `Authorizer` deletes expired keys itself.

## auth_refresh_families (`RefreshFamily`)

One row per login session.

| Column | Type | Notes |
|---|---|---|
| `id` | string(36), primary key | The family's UUID (the token's `fam` claim). |
| `subject` | string(255), indexed | The user. |
| `revoked` | bool | Set by logout, reuse detection and `RevokeAllSessions`. |
| `expires_at` | time, indexed | The latest expiry of any token in the family. |

Revoked families are kept until they expire. While a revoked row exists, a refresh that was already in progress when the session was revoked cannot add a token to it.

## auth_refresh_tokens (`RefreshToken`)

One row per issued refresh token.

| Column | Type | Notes |
|---|---|---|
| `id` | string(36), primary key | The token's UUID (`jti` claim). |
| `parent_id` | string(36) | The token this one replaced, or the nil UUID for a login's first token. |
| `family_id` | string(36), indexed | The session. |
| `subject` | string(255), indexed | The user. |
| `issued_at` | time | |
| `expires_at` | time, indexed | The token's expiry plus the auth package's `Leeway`. |
| `used_at` | time, nullable | When the token was first exchanged. `NULL` means unused. |

Used tokens are kept until they expire. If one is presented again after the reuse grace window, the auth package sees a non-null `used_at` and revokes the whole family.

There is no foreign key from `family_id` to `auth_refresh_families`. The store always deletes tokens before or together with their family.

## auth_refresh_subjects (`RefreshSubject`)

| Column | Type | Notes |
|---|---|---|
| `subject` | string(255), primary key | The user. |
| `locked_at` | time | When the row was last locked. Informational only. |

This table exists only to be locked. A login and `RevokeAllSessions` both upsert the user's row first, so the two cannot interleave (see [Databases and Concurrency](Databases-and-Concurrency.md)). The table holds one row per user who has ever logged in or been revoked. Rows are never deleted. They are small, and deleting one is harmless but saves nothing.

## Purging

`PurgeExpiredRefreshTokens(ctx, now)` deletes, in batches of 1000:

```sql
SELECT id FROM auth_refresh_tokens WHERE expires_at < :now LIMIT 1000;
DELETE FROM auth_refresh_tokens WHERE id IN (...) AND expires_at < :now;
-- repeated until a batch comes back short, then the same for auth_refresh_families
```

Selecting IDs first and deleting them in a second statement works the same on every database; `DELETE ... LIMIT` and `LIMIT` inside an `IN` subquery do not (MySQL rejects the latter). The delete re-checks `expires_at`, so a session extended between the two statements is kept. The `Authorizer` calls this method in the background; see [Getting Started](Getting-Started.md#expired-refresh-tokens).
