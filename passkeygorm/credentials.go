package passkeygorm

import (
	"context"
	"fmt"
	"math"

	"github.com/tpyle/auth/passkey"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ListCredentials implements [passkey.CredentialStore]. Credentials are
// ordered by registration time.
func (s *Store) ListCredentials(ctx context.Context, subject string) ([]passkey.Credential, error) {
	var rows []Credential
	err := s.db.WithContext(ctx).Where("subject = ?", subject).Order("created_at, id").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]passkey.Credential, 0, len(rows))
	for _, r := range rows {
		c, err := r.credential()
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// CreateCredential implements [passkey.CredentialStore]. It fails with an
// error wrapping [passkey.ErrCredentialExists] if any user already has a
// credential with the same ID.
func (s *Store) CreateCredential(ctx context.Context, c passkey.Credential) error {
	if len(c.ID) == 0 {
		return fmt.Errorf("passkeygorm: credential has no ID")
	}
	row := Credential{
		ID:                c.ID,
		Subject:           c.Subject,
		PublicKey:         c.PublicKey,
		SignCount:         int64(c.SignCount),
		AAGUID:            c.AAGUID,
		Transports:        c.Transports,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		UserVerified:      c.UserVerified,
		BackupEligible:    c.BackupEligible,
		BackupState:       c.BackupState,
		CloneWarning:      c.CloneWarning,
		Label:             c.Label,
		CreatedAt:         c.CreatedAt.UTC(),
	}
	if !c.LastUsedAt.IsZero() {
		t := c.LastUsedAt.UTC()
		row.LastUsedAt = &t
	}
	if row.Transports == nil {
		row.Transports = []string{}
	}
	// ON CONFLICT DO NOTHING detects a duplicate ID the same way on every
	// database, without parsing driver-specific errors.
	res := s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return passkey.ErrCredentialExists
	}
	return nil
}

// RecordCredentialUse implements [passkey.CredentialStore]. A single UPDATE
// keeps the larger signature counter and never clears UserVerified or
// CloneWarning, so racing logins cannot undo each other.
func (s *Store) RecordCredentialUse(ctx context.Context, u passkey.CredentialUse) error {
	count := int64(u.SignCount)
	updates := map[string]any{
		"sign_count":    gorm.Expr("CASE WHEN sign_count < ? THEN ? ELSE sign_count END", count, count),
		"backup_state":  u.BackupState,
		"user_verified": gorm.Expr("user_verified OR ?", u.UserVerified),
		"clone_warning": gorm.Expr("clone_warning OR ?", u.CloneWarning),
	}
	if !u.UsedAt.IsZero() {
		updates["last_used_at"] = u.UsedAt.UTC()
	}
	return s.db.WithContext(ctx).Model(&Credential{}).Where("id = ?", u.ID).Updates(updates).Error
}

// DeleteCredential implements [passkey.CredentialStore]. It returns an error
// wrapping [passkey.ErrCredentialNotFound] unless subject has a credential
// with the given ID.
func (s *Store) DeleteCredential(ctx context.Context, subject string, id []byte) error {
	res := s.db.WithContext(ctx).Where("id = ? AND subject = ?", id, subject).Delete(&Credential{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return passkey.ErrCredentialNotFound
	}
	return nil
}

// credential converts the row to the passkey package's representation.
func (r Credential) credential() (passkey.Credential, error) {
	if r.SignCount < 0 || r.SignCount > math.MaxUint32 {
		return passkey.Credential{}, fmt.Errorf("passkeygorm: credential %x: sign count %d out of range", r.ID, r.SignCount)
	}
	c := passkey.Credential{
		ID:                r.ID,
		Subject:           r.Subject,
		PublicKey:         r.PublicKey,
		SignCount:         uint32(r.SignCount),
		AAGUID:            r.AAGUID,
		Transports:        r.Transports,
		AttestationType:   r.AttestationType,
		AttestationFormat: r.AttestationFormat,
		UserVerified:      r.UserVerified,
		BackupEligible:    r.BackupEligible,
		BackupState:       r.BackupState,
		CloneWarning:      r.CloneWarning,
		Label:             r.Label,
		CreatedAt:         r.CreatedAt,
	}
	if r.LastUsedAt != nil {
		c.LastUsedAt = *r.LastUsedAt
	}
	return c, nil
}
