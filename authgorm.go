package authgorm

import (
	"context"
	"time"

	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
)

// Interface checks.
var (
	_ auth.UserStore           = (*Store)(nil)
	_ auth.PasswordHashUpdater = (*Store)(nil)
	_ auth.KeyStore            = (*Store)(nil)
	_ auth.RefreshTokenStore   = (*Store)(nil)
	_ auth.RefreshTokenPurger  = (*Store)(nil)
)

// defaultPurgeBatchSize is how many rows each statement of
// PurgeExpiredRefreshTokens deletes.
const defaultPurgeBatchSize = 1000

// Store implements every auth store interface on one GORM connection. It is
// safe for concurrent use.
type Store struct {
	db             *gorm.DB
	purgeBatchSize int
}

// New returns a Store that uses db for every operation. Each call passes its
// context on to db.
func New(db *gorm.DB) *Store {
	return &Store{db: db, purgeBatchSize: defaultPurgeBatchSize}
}

// Migrate creates or updates the tables the store uses (see [User],
// [SigningKey], [RefreshFamily], [RefreshToken] and [RefreshSubject]). It
// is safe to call on every start.
func (s *Store) Migrate(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(
		&User{},
		&SigningKey{},
		&RefreshFamily{},
		&RefreshToken{},
		&RefreshSubject{},
	)
}

// Options returns the auth options that make an Authorizer use s as its
// user, key and refresh-token store. Append further options to the result:
//
//	auth.New(ctx, append(store.Options(), auth.WithIssuer("me"))...)
func (s *Store) Options() []auth.Option {
	return []auth.Option{
		auth.WithUserStore(s),
		auth.WithKeyStore(s),
		auth.WithRefreshTokenStore(s),
	}
}

// User is a row of the "users" table. Refresh tokens are not linked to it,
// so deleting a user does not end their sessions; call
// Authorizer.RevokeAllSessions after deleting the user.
type User struct {
	gorm.Model

	// UserSubject is the username passed to Authenticate and Login.
	UserSubject string `gorm:"uniqueIndex;size:255;not null"`
	// HashedPassword is a PHC-encoded Argon2id hash, as produced by
	// auth.HashPassword.
	HashedPassword string `gorm:"not null"`
}

// SigningKey is a row of the "auth_signing_keys" table: the public half of
// one signing key.
type SigningKey struct {
	// ID is the key's UUID, used as the "kid" header of the tokens it signs.
	ID string `gorm:"primaryKey;size:36"`
	// PublicKey is the PKIX DER encoding of a P-256 public key.
	PublicKey []byte `gorm:"not null"`
	// CreatedAt is when the key was generated.
	CreatedAt time.Time `gorm:"not null;autoCreateTime:false"`
	// ExpiresAt is when the key may be deleted. NULL means never.
	ExpiresAt *time.Time
}

// TableName implements GORM's tabler interface.
func (SigningKey) TableName() string { return "auth_signing_keys" }

// RefreshFamily is a row of the "auth_refresh_families" table: one login
// session. Revoked families are kept until they expire so that a refresh in
// flight during the revocation cannot add a token to them.
type RefreshFamily struct {
	// ID is the family's UUID.
	ID string `gorm:"primaryKey;size:36"`
	// Subject is the user the session belongs to.
	Subject string `gorm:"size:255;not null;index"`
	// Revoked is set when the session is logged out or its tokens are reused.
	Revoked bool `gorm:"not null;default:false"`
	// ExpiresAt is the latest expiry of any token in the family.
	ExpiresAt time.Time `gorm:"not null;index"`
}

// TableName implements GORM's tabler interface.
func (RefreshFamily) TableName() string { return "auth_refresh_families" }

// RefreshToken is a row of the "auth_refresh_tokens" table: the server-side
// state of one refresh token.
type RefreshToken struct {
	// ID is the token's UUID ("jti" claim).
	ID string `gorm:"primaryKey;size:36"`
	// ParentID is the UUID of the token this one replaced, or the nil UUID
	// for the first token of a login.
	ParentID string `gorm:"size:36;not null"`
	// FamilyID references RefreshFamily.ID.
	FamilyID string `gorm:"size:36;not null;index"`
	// Subject is the user the token was issued to.
	Subject string `gorm:"size:255;not null;index"`
	// IssuedAt is when the token was created.
	IssuedAt time.Time `gorm:"not null"`
	// ExpiresAt is when the token can no longer be accepted.
	ExpiresAt time.Time `gorm:"not null;index"`
	// UsedAt is when the token was first exchanged. NULL means unused.
	UsedAt *time.Time
}

// TableName implements GORM's tabler interface.
func (RefreshToken) TableName() string { return "auth_refresh_tokens" }

// RefreshSubject is a row of the "auth_refresh_subjects" table. Its only
// purpose is to be locked: logins and RevokeRefreshTokensForSubject lock the
// subject's row so that a session cannot be created while all of the
// subject's sessions are being revoked. Rows are never deleted.
type RefreshSubject struct {
	// Subject is the username.
	Subject string `gorm:"primaryKey;size:255"`
	// LockedAt is when the row was last locked. It is informational.
	LockedAt time.Time `gorm:"not null"`
}

// TableName implements GORM's tabler interface.
func (RefreshSubject) TableName() string { return "auth_refresh_subjects" }
