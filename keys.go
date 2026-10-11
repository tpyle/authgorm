package authgorm

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
)

// StoreKey implements [auth.KeyStore].
func (s *Store) StoreKey(ctx context.Context, key *auth.VerificationKey) error {
	der, err := key.MarshalPublicKey()
	if err != nil {
		return err
	}
	row := SigningKey{
		ID:        key.ID.String(),
		PublicKey: der,
		CreatedAt: key.CreatedAt.UTC(),
		ExpiresAt: nullableTime(key.ExpiresAt),
	}
	return s.db.WithContext(ctx).Create(&row).Error
}

// ListKeys implements [auth.KeyStore].
func (s *Store) ListKeys(ctx context.Context) ([]*auth.VerificationKey, error) {
	var rows []SigningKey
	if err := s.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, err
	}
	keys := make([]*auth.VerificationKey, 0, len(rows))
	for _, row := range rows {
		id, err := uuid.Parse(row.ID)
		if err != nil {
			return nil, fmt.Errorf("authgorm: signing key %q: %w", row.ID, err)
		}
		pub, err := auth.ParsePublicKey(row.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("authgorm: signing key %s: %w", id, err)
		}
		k := &auth.VerificationKey{ID: id, PublicKey: pub, CreatedAt: row.CreatedAt}
		if row.ExpiresAt != nil {
			k.ExpiresAt = *row.ExpiresAt
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// DeleteKeys implements [auth.KeyStore]. IDs that do not exist are ignored.
func (s *Store) DeleteKeys(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).Where("id IN ?", uuidStrings(ids)).Delete(&SigningKey{}).Error
}

// nullableTime maps the zero time to NULL. Non-zero times are stored in UTC
// so that databases which compare times as text (SQLite) order them
// correctly.
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// uuidStrings returns the string form of each ID, as stored in the id
// columns.
func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
