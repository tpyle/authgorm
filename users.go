package authgorm

import (
	"context"
	"errors"
	"fmt"

	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
)

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

// SetPasswordHash creates the user if it does not exist, or replaces its
// hash if it does. encodedHash should come from auth.HashPassword or
// Authorizer.HashPassword.
//
// The username of a soft-deleted user stays taken: creating it again fails
// with a unique-constraint error until the row is deleted permanently
// (db.Unscoped().Delete).
func (s *Store) SetPasswordHash(ctx context.Context, username, encodedHash string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&User{}).Where("user_subject = ?", username).Update("hashed_password", encodedHash)
		if res.Error != nil || res.RowsAffected > 0 {
			return res.Error
		}
		return tx.Create(&User{UserSubject: username, HashedPassword: encodedHash}).Error
	})
}
