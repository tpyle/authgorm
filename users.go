package authgorm

import (
	"context"
	"errors"
	"fmt"

	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrUserExists is returned, wrapped, by [Store.CreateUser] when the
// username is taken, and by [Store.SetPasswordHash] when it belongs to a
// soft-deleted user.
var ErrUserExists = errors.New("authgorm: user already exists")

// LookupPasswordHash implements [auth.UserStore]. Soft-deleted users are not
// found.
func (s *Store) LookupPasswordHash(ctx context.Context, username string) (string, error) {
	var u User
	err := s.db.WithContext(ctx).Where("user_subject = ?", username).Take(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("%w: %q", auth.ErrUserNotFound, username)
	}
	if err != nil {
		return "", err
	}
	return u.HashedPassword, nil
}

// UpdatePasswordHash implements [auth.PasswordHashUpdater]. It is a
// compare-and-swap: the hash is replaced only if it is still oldHash.
func (s *Store) UpdatePasswordHash(ctx context.Context, username, oldHash, newHash string) error {
	return s.db.WithContext(ctx).Model(&User{}).
		Where("user_subject = ? AND hashed_password = ?", username, oldHash).
		Update("hashed_password", newHash).Error
}

// CreateUser creates a user with the given password hash. It returns an
// error wrapping [ErrUserExists] if the username is taken, so it is safe to
// call from a sign-up handler: of two concurrent sign-ups for one username,
// exactly one succeeds. encodedHash should come from auth.HashPassword or
// Authorizer.HashPassword.
//
// The username of a soft-deleted user stays taken until the row is deleted
// permanently (db.Unscoped().Delete).
func (s *Store) CreateUser(ctx context.Context, username, encodedHash string) error {
	created, err := insertUser(s.db.WithContext(ctx), username, encodedHash)
	if err == nil && !created {
		return fmt.Errorf("%w: %q", ErrUserExists, username)
	}
	return err
}

// SetPasswordHash creates the user if it does not exist, or replaces its
// hash if it does. Concurrent calls for one username all succeed, and the
// last one wins. To register new users without replacing existing ones, use
// [Store.CreateUser]. encodedHash should come from auth.HashPassword or
// Authorizer.HashPassword.
//
// The username of a soft-deleted user stays taken: setting its hash returns
// an error wrapping [ErrUserExists] until the row is deleted permanently
// (db.Unscoped().Delete).
func (s *Store) SetPasswordHash(ctx context.Context, username, encodedHash string) error {
	db := s.db.WithContext(ctx)
	created, err := insertUser(db, username, encodedHash)
	if err != nil || created {
		return err
	}
	res := db.Model(&User{}).Where("user_subject = ?", username).Update("hashed_password", encodedHash)
	if res.Error != nil || res.RowsAffected > 0 {
		return res.Error
	}
	// No live row was updated, so the user is soft-deleted, unless the
	// driver counts only changed rows (MySQL) and the hash was already set.
	_, err = s.LookupPasswordHash(ctx, username)
	if errors.Is(err, auth.ErrUserNotFound) {
		return fmt.Errorf("%w: %q belongs to a soft-deleted user", ErrUserExists, username)
	}
	return err
}

// insertUser inserts a user unless the username is taken, and reports
// whether it did. A single INSERT ... ON CONFLICT DO NOTHING cannot race
// with another insert the way a check followed by an insert can.
func insertUser(db *gorm.DB, username, encodedHash string) (bool, error) {
	res := db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&User{UserSubject: username, HashedPassword: encodedHash})
	return res.RowsAffected > 0, res.Error
}
