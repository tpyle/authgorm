package passkeygorm

import (
	"context"
	"errors"
	"time"

	"uuid"

	"github.com/tpyle/auth/passkey"
	"gorm.io/gorm"
)

// SaveCeremony implements [passkey.CeremonyStore]. At most once per
// [WithCeremonyPurgeInterval] it first deletes expired ceremonies. A failed
// purge does not fail the call; it is retried on a later one.
func (s *Store) SaveCeremony(ctx context.Context, id uuid.UUID, data []byte, expiresAt time.Time) error {
	if now, ok := s.purgeDue(); ok {
		_, _ = s.PurgeExpiredCeremonies(ctx, now)
	}
	row := Ceremony{ID: id.String(), Data: data, ExpiresAt: expiresAt.UTC()}
	return s.db.WithContext(ctx).Create(&row).Error
}

// ConsumeCeremony implements [passkey.CeremonyStore]. The ceremony is read
// and then deleted; only the caller whose DELETE removes the row gets its
// data, so a ceremony is finished at most once even when two requests race.
// Expired ceremonies are deleted too, but reported as not found.
func (s *Store) ConsumeCeremony(ctx context.Context, id uuid.UUID, now time.Time) ([]byte, error) {
	db := s.db.WithContext(ctx)
	var row Ceremony
	err := db.Where("id = ?", id.String()).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, passkey.ErrCeremonyNotFound
	}
	if err != nil {
		return nil, err
	}
	res := db.Where("id = ?", row.ID).Delete(&Ceremony{})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 || !now.Before(row.ExpiresAt) {
		return nil, passkey.ErrCeremonyNotFound
	}
	return row.Data, nil
}

// PurgeExpiredCeremonies deletes ceremonies that expired before now, in
// batches of 1000, and returns how many it deleted. [Store.SaveCeremony]
// calls it periodically; call it directly to purge on your own schedule.
func (s *Store) PurgeExpiredCeremonies(ctx context.Context, now time.Time) (int64, error) {
	db := s.db.WithContext(ctx)
	now = now.UTC()
	var total int64
	for {
		// Selecting IDs first is portable; DELETE ... LIMIT is not.
		var ids []string
		err := db.Model(&Ceremony{}).Where("expires_at < ?", now).Limit(s.purgeBatchSize).Pluck("id", &ids).Error
		if err != nil || len(ids) == 0 {
			return total, err
		}
		res := db.Where("id IN ?", ids).Delete(&Ceremony{})
		total += res.RowsAffected
		// A batch that deletes nothing would be selected again forever.
		if res.Error != nil || len(ids) < s.purgeBatchSize || res.RowsAffected == 0 {
			return total, res.Error
		}
	}
}

// purgeDue reports whether SaveCeremony should purge now, and if so records
// that it did. A clock that moved backwards also purges.
func (s *Store) purgeDue() (time.Time, bool) {
	if s.purgeInterval <= 0 {
		return time.Time{}, false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastPurge.IsZero() && !now.Before(s.lastPurge) && now.Before(s.lastPurge.Add(s.purgeInterval)) {
		return time.Time{}, false
	}
	s.lastPurge = now
	return now, true
}
