package authgorm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// CreateRefreshToken implements [auth.RefreshTokenStore].
//
// A login (no ParentID) locks the subject's [RefreshSubject] row and inserts
// a new family. A refresh locks the family row with SELECT ... FOR UPDATE
// and fails with [auth.ErrTokenRevoked] if the family is revoked or gone.
// The revoke methods take the same locks, so a token created concurrently
// with a revocation is either rejected or deleted by it. Locks are always
// taken subject first, then family.
func (s *Store) CreateRefreshToken(ctx context.Context, rec auth.RefreshTokenRecord) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		expiresAt := rec.ExpiresAt.UTC()
		if rec.ParentID == uuid.Nil {
			if err := lockSubject(tx, rec.Subject); err != nil {
				return err
			}
			fam := RefreshFamily{ID: rec.FamilyID.String(), Subject: rec.Subject, ExpiresAt: expiresAt}
			if err := tx.Create(&fam).Error; err != nil {
				return err
			}
		} else {
			var fam RefreshFamily
			err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
				Where("id = ?", rec.FamilyID.String()).Take(&fam).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: family %s no longer exists", auth.ErrTokenRevoked, rec.FamilyID)
			}
			if err != nil {
				return err
			}
			if fam.Revoked {
				return fmt.Errorf("%w: family %s", auth.ErrTokenRevoked, rec.FamilyID)
			}
			// The revoke methods find tokens by their own subject and
			// families by theirs, so the two must agree.
			if fam.Subject != rec.Subject {
				return fmt.Errorf("authgorm: token for %q cannot join family %s of %q", rec.Subject, rec.FamilyID, fam.Subject)
			}
			if expiresAt.After(fam.ExpiresAt) {
				if err := tx.Model(&fam).Update("expires_at", expiresAt).Error; err != nil {
					return err
				}
			}
		}
		row := RefreshToken{
			ID:        rec.ID.String(),
			ParentID:  rec.ParentID.String(),
			FamilyID:  rec.FamilyID.String(),
			Subject:   rec.Subject,
			IssuedAt:  rec.IssuedAt.UTC(),
			ExpiresAt: expiresAt,
		}
		return tx.Create(&row).Error
	})
}

// ConsumeRefreshToken implements [auth.RefreshTokenStore].
//
// The record is read, then claimed with a conditional UPDATE (used_at IS
// NULL), so exactly one of any number of concurrent callers sees the token
// as unused. A caller that loses the race reads the record again to get the
// winner's UsedAt.
func (s *Store) ConsumeRefreshToken(ctx context.Context, id uuid.UUID, now time.Time) (auth.RefreshTokenRecord, error) {
	db := s.db.WithContext(ctx)
	row, err := findRefreshToken(db, id)
	if err != nil {
		return auth.RefreshTokenRecord{}, err
	}
	if row.UsedAt == nil {
		res := db.Model(&RefreshToken{}).
			Where("id = ? AND used_at IS NULL", row.ID).
			Update("used_at", now.UTC())
		if res.Error != nil {
			return auth.RefreshTokenRecord{}, res.Error
		}
		if res.RowsAffected == 0 {
			// Another caller used the token (or revoked it) first.
			if row, err = findRefreshToken(db, id); err != nil {
				return auth.RefreshTokenRecord{}, err
			}
		}
	}
	return row.record()
}

// RevokeRefreshTokenFamily implements [auth.RefreshTokenStore].
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error {
	id := familyID.String()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&RefreshFamily{}).Where("id = ?", id).Update("revoked", true).Error; err != nil {
			return err
		}
		return tx.Where("family_id = ?", id).Delete(&RefreshToken{}).Error
	})
}

// RevokeRefreshTokensForSubject implements [auth.RefreshTokenStore]. It
// locks the subject's row first, which waits for logins in progress.
func (s *Store) RevokeRefreshTokensForSubject(ctx context.Context, subject string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockSubject(tx, subject); err != nil {
			return err
		}
		if err := tx.Model(&RefreshFamily{}).Where("subject = ?", subject).Update("revoked", true).Error; err != nil {
			return err
		}
		return tx.Where("subject = ?", subject).Delete(&RefreshToken{}).Error
	})
}

// PurgeExpiredRefreshTokens deletes refresh tokens and families that expired
// before now, and returns how many rows were deleted. It implements
// [auth.RefreshTokenPurger], so every Authorizer using the store calls it in
// the background (see auth.Config.RefreshPurgeInterval); call it directly
// only to purge on a schedule of your own.
//
// Rows are deleted in batches of 1000, so a large backlog is cleared in
// short statements rather than one long one. Concurrent purges, for example
// from several instances, are safe.
func (s *Store) PurgeExpiredRefreshTokens(ctx context.Context, now time.Time) (int64, error) {
	db := s.db.WithContext(ctx)
	now = now.UTC()
	// A family expires no earlier than its last token, so deleting tokens
	// first never leaves a token without its family.
	total, err := s.purgeExpired(db, &RefreshToken{}, now)
	if err != nil {
		return total, err
	}
	n, err := s.purgeExpired(db, &RefreshFamily{}, now)
	return total + n, err
}

// purgeExpired deletes rows of model whose expires_at is before now, at
// most s.purgeBatchSize per statement. IDs are selected first and deleted
// in a second statement, rather than with DELETE ... LIMIT or a LIMIT
// subquery, because neither is portable. The delete re-checks expires_at,
// so a family extended in between is kept.
func (s *Store) purgeExpired(db *gorm.DB, model any, now time.Time) (int64, error) {
	var total int64
	for {
		var ids []string
		err := db.Model(model).Where("expires_at < ?", now).Limit(s.purgeBatchSize).Pluck("id", &ids).Error
		if err != nil || len(ids) == 0 {
			return total, err
		}
		res := db.Where("id IN ? AND expires_at < ?", ids, now).Delete(model)
		total += res.RowsAffected
		// A batch that deletes nothing would be selected again forever.
		if res.Error != nil || len(ids) < s.purgeBatchSize || res.RowsAffected == 0 {
			return total, res.Error
		}
	}
}

// lockSubject upserts the subject's RefreshSubject row, which locks it until
// tx ends.
func lockSubject(tx *gorm.DB, subject string) error {
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "subject"}},
		DoUpdates: clause.AssignmentColumns([]string{"locked_at"}),
	}).Create(&RefreshSubject{Subject: subject, LockedAt: time.Now().UTC()}).Error
}

// findRefreshToken loads a token row by ID. A missing row is reported as
// an error wrapping [auth.ErrRefreshTokenNotFound].
func findRefreshToken(db *gorm.DB, id uuid.UUID) (RefreshToken, error) {
	var row RefreshToken
	err := db.Where("id = ?", id.String()).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return row, fmt.Errorf("%w: %s", auth.ErrRefreshTokenNotFound, id)
	}
	return row, err
}

// record converts the row to the auth package's representation.
func (r RefreshToken) record() (auth.RefreshTokenRecord, error) {
	var rec auth.RefreshTokenRecord
	var err error
	if rec.ID, err = uuid.Parse(r.ID); err != nil {
		return auth.RefreshTokenRecord{}, fmt.Errorf("authgorm: refresh token %q: %w", r.ID, err)
	}
	if rec.ParentID, err = uuid.Parse(r.ParentID); err != nil {
		return auth.RefreshTokenRecord{}, fmt.Errorf("authgorm: refresh token %s parent %q: %w", rec.ID, r.ParentID, err)
	}
	if rec.FamilyID, err = uuid.Parse(r.FamilyID); err != nil {
		return auth.RefreshTokenRecord{}, fmt.Errorf("authgorm: refresh token %s family %q: %w", rec.ID, r.FamilyID, err)
	}
	rec.Subject = r.Subject
	rec.IssuedAt = r.IssuedAt
	rec.ExpiresAt = r.ExpiresAt
	if r.UsedAt != nil {
		rec.UsedAt = *r.UsedAt
	}
	return rec, nil
}
