// Package authgorm provides a GORM-based implementation for authentication storage.
// It implements the necessary interfaces for storing and retrieving users, signing keys,
// and refresh tokens using GORM as the ORM layer.
package authgorm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth"
	"gorm.io/gorm"
)

var (
	// ErrNotAllKeysDeleted is returned when a delete operation fails to delete all requested signing keys.
	ErrNotAllKeysDeleted = errors.New("not all signing keys were deleted")
)

// AuthGorm provides GORM-based storage for authentication data.
// It manages database operations for users, signing keys, and refresh tokens.
type AuthGorm struct {
	dbConnection *gorm.DB
}

// User represents a user in the authentication system.
// It stores the user's subject identifier and hashed password.
type User struct {
	gorm.Model

	// UserSubject is the unique identifier for the user (could be an email or username).
	UserSubject string `gorm:"unique,not null"`
	// HashedPassword is the bcrypt or other hashed password for the user.
	HashedPassword string `gorm:"not null"`
}

// SigningKey represents a cryptographic signing key used for JWT token signing.
// It stores the public key portion of a key pair along with metadata.
type SigningKey struct {
	gorm.Model

	// KeyID is the unique identifier for the signing key.
	KeyID string `gorm:"unique,not null"`
	// PublicKey is the binary representation of the ECDSA public key.
	PublicKey []byte `gorm:"not null"`
	// CreationTime is the Unix timestamp when the key was created.
	CreationTime int64 `gorm:"not null"`
}

// RefreshToken represents a long-lived token that can be used to obtain new access tokens.
// It is associated with a user and contains random data for security.
type RefreshToken struct {
	gorm.Model

	// TokenID is the unique identifier for the refresh token.
	TokenID string `gorm:"unique,not null"`
	// UserID is the foreign key reference to the User.
	UserID uint `gorm:"not null"`
	// User is the associated User record.
	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
	// Random contains cryptographically random bytes for token verification.
	Random []byte `gorm:"not null"`
}

// Migrate runs auto-migration for all authentication-related tables.
// It creates or updates the User, SigningKey, and RefreshToken tables in the database.
// Returns an error if the migration fails.
func (ag *AuthGorm) Migrate() error {
	return ag.dbConnection.AutoMigrate(&User{}, &SigningKey{}, &RefreshToken{})
}

// StoreNewSigningKey stores a new signing key in the database.
// It converts the key pair's public key to binary format and stores it with its metadata.
// Returns an error if the key cannot be serialized or stored.
func (ag *AuthGorm) StoreNewSigningKey(kp *auth.KeyPairWithCreationTime) error {
	keyBytes, err := kp.GetPublicKeyAsBinary()
	if err != nil {
		return err
	}

	signingKey := SigningKey{
		KeyID:        kp.ID.String(),
		PublicKey:    keyBytes,
		CreationTime: kp.CreationTime.Unix(),
	}

	err = gorm.G[SigningKey](ag.dbConnection).Create(context.Background(), &signingKey)
	if err != nil {
		return err
	}

	return nil
}

// GetSigningKeyByID retrieves a signing key from the database by its ID.
// It reconstructs the KeyPairWithCreationTime from the stored binary public key data.
// Returns an error if the key is not found or cannot be deserialized.
func (ag *AuthGorm) GetSigningKeyByID(keyID uuid.UUID) (*auth.KeyPairWithCreationTime, error) {
	signingKey, err := gorm.G[SigningKey](ag.dbConnection).Where("key_id = ?", keyID.String()).First(context.Background())
	if err != nil {
		return nil, err
	}

	pk, err := auth.GetECDSAPublicKeyFromBinary(signingKey.PublicKey)
	if err != nil {
		return nil, err
	}

	kp := &auth.KeyPairWithCreationTime{
		ID:           keyID,
		PublicKey:    pk,
		CreationTime: time.Unix(signingKey.CreationTime, 0),
	}

	return kp, nil
}

// DeleteSigningKeysByIDs deletes multiple signing keys from the database by their IDs.
// It verifies that all requested keys were deleted and returns ErrNotAllKeysDeleted if not.
// This is typically used for removing expired signing keys.
func (ag *AuthGorm) DeleteSigningKeysByIDs(keyIDs []uuid.UUID) error {
	var strIDs []string
	for _, id := range keyIDs {
		strIDs = append(strIDs, id.String())
	}

	count, err := gorm.G[SigningKey](ag.dbConnection).Where("key_id IN ?", strIDs).Delete(context.Background())
	if err != nil {
		return err
	}

	if count != len(keyIDs) {
		return fmt.Errorf("%w: expected %d, got %d", ErrNotAllKeysDeleted, len(keyIDs), count)
	}

	return nil
}

// GetPasswordForUserSubject retrieves the hashed password for a user by their subject identifier.
// The user subject can be an email, username, or other unique identifier.
// Returns an error if the user is not found.
func (ag *AuthGorm) GetPasswordForUserSubject(userSubject string) (string, error) {
	user, err := gorm.G[User](ag.dbConnection).Where("user_subject = ?", userSubject).First(context.Background())
	if err != nil {
		return "", err
	}

	return user.HashedPassword, nil
}

// GetRefreshTokenByID retrieves a refresh token from the database by its ID.
// It preloads the associated user data and reconstructs the auth.RefreshToken object.
// Returns an error if the token is not found or cannot be parsed.
func (ag *AuthGorm) GetRefreshTokenByID(tokenID uuid.UUID) (*auth.RefreshToken, error) {
	var refreshToken RefreshToken
	err := ag.dbConnection.Preload("User").Where("token_id = ?", tokenID.String()).First(&refreshToken).Error
	if err != nil {
		return nil, err
	}

	rtuuid, err := uuid.Parse(refreshToken.TokenID)
	if err != nil {
		return nil, err
	}

	rtData := &auth.RefreshToken{
		ID:      rtuuid,
		Subject: refreshToken.User.UserSubject,
		Rand:    refreshToken.Random,
	}

	return rtData, nil
}

// StoreNewRefreshToken stores a new refresh token in the database.
// Returns an error if the user doesn't exist or the token cannot be stored.
func (ag *AuthGorm) StoreNewRefreshToken(rt *auth.RefreshToken) error {
	// Look up the existing user first
	user, err := gorm.G[User](ag.dbConnection).Where("user_subject = ?", rt.Subject).First(context.Background())
	if err != nil {
		return err
	}

	// Create the refresh token with the existing user's ID
	refreshToken := RefreshToken{
		TokenID: rt.ID.String(),
		Random:  rt.Rand,
		UserID:  user.ID,
	}

	return gorm.G[RefreshToken](ag.dbConnection).Create(context.Background(), &refreshToken)
}

// DeleteRefreshTokenByID deletes a refresh token from the database by its ID.
// This is typically used when logging out or revoking a refresh token.
// Returns an error if the deletion fails.
func (ag *AuthGorm) DeleteRefreshTokenByID(tokenID uuid.UUID) error {
	_, err := gorm.G[RefreshToken](ag.dbConnection).Where("token_id = ?", tokenID.String()).Delete(context.Background())
	return err
}

// NewAuthGorm creates a new AuthGorm instance with the given database connection.
// The provided GORM database connection will be used for all database operations.
func NewAuthGorm(dbConnection *gorm.DB) *AuthGorm {
	return &AuthGorm{
		dbConnection: dbConnection,
	}
}

// AsOptions returns an auth.Option that configures an auth system to use this AuthGorm instance.
// It wires up all the necessary function callbacks for user lookup, token storage, and key management.
// This allows AuthGorm to be easily integrated with the auth package.
func (ag *AuthGorm) AsOptions() auth.Option {
	return func(options *auth.Options) {
		options.StoreNewSigningKeyFunc = ag.StoreNewSigningKey
		options.GetSigningKeyFunc = ag.GetSigningKeyByID
		options.DeleteExpiredSigningKeysFunc = ag.DeleteSigningKeysByIDs
		options.LookupUserPasswordFunc = ag.GetPasswordForUserSubject
		options.LookupRefreshTokenFunc = ag.GetRefreshTokenByID
		options.StoreRefreshTokenFunc = ag.StoreNewRefreshToken
		options.DeleteRefreshTokenFunc = ag.DeleteRefreshTokenByID
	}
}
