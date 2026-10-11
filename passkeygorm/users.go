package passkeygorm

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/tpyle/auth/passkey"
	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// LookupUser implements [passkey.UserStore].
func (s *Store) LookupUser(ctx context.Context, subject string) (passkey.User, error) {
	return s.findUser(ctx, "subject = ?", subject)
}

// LookupUserByHandle implements [passkey.UserStore].
func (s *Store) LookupUserByHandle(ctx context.Context, handle []byte) (passkey.User, error) {
	if len(handle) == 0 {
		return passkey.User{}, fmt.Errorf("%w: empty handle", auth.ErrUserNotFound)
	}
	u, err := s.findUser(ctx, "handle = ?", handle)
	// Guard against databases whose comparison is not byte for byte.
	if err == nil && !bytes.Equal(u.Handle, handle) {
		return passkey.User{}, fmt.Errorf("%w: unknown handle", auth.ErrUserNotFound)
	}
	return u, err
}

func (s *Store) findUser(ctx context.Context, query string, arg any) (passkey.User, error) {
	var row User
	err := s.db.WithContext(ctx).Where(query, arg).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return passkey.User{}, fmt.Errorf("%w: no passkey user matches", auth.ErrUserNotFound)
	}
	if err != nil {
		return passkey.User{}, err
	}
	return passkey.User{Subject: row.Subject, Handle: row.Handle, Name: row.Name, DisplayName: row.DisplayName}, nil
}

// EnsureUser returns the WebAuthn identity of subject, creating it with a
// new handle from passkey.NewUserHandle if it does not exist yet. name is
// what authenticators show when the user picks a passkey (empty means
// subject), and displayName a friendlier version of it (empty means name).
//
// An existing user is returned unchanged, so it is safe to call before every
// registration. Concurrent calls for the same subject all return the same
// handle.
func (s *Store) EnsureUser(ctx context.Context, subject, name, displayName string) (passkey.User, error) {
	if subject == "" {
		return passkey.User{}, errors.New("passkeygorm: subject must not be empty")
	}
	if name == "" {
		name = subject
	}
	row := User{
		Subject:     subject,
		Handle:      passkey.NewUserHandle(),
		Name:        name,
		DisplayName: displayName,
		CreatedAt:   s.now().UTC(),
	}
	db := s.db.WithContext(ctx)
	err := db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "subject"}}, DoNothing: true}).Create(&row).Error
	if err != nil {
		return passkey.User{}, err
	}
	return s.LookupUser(ctx, subject)
}

// DeleteUser deletes subject's WebAuthn identity and every credential
// registered to it. Call it when deleting the account. Deleting an unknown
// subject is not an error. A registration that finishes concurrently either
// has its credential deleted too or fails with [auth.ErrUserNotFound].
func (s *Store) DeleteUser(ctx context.Context, subject string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// The user row goes first: deleting it locks it, which is what
		// CreateCredential waits on (see there).
		if err := tx.Where("subject = ?", subject).Delete(&User{}).Error; err != nil {
			return err
		}
		return tx.Where("subject = ?", subject).Delete(&Credential{}).Error
	})
}
