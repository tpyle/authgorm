package authgorm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// postgresDSNEnv names the environment variable that enables the PostgreSQL
// backend in tests, e.g. "host=localhost user=postgres password=postgres
// dbname=authgorm_test sslmode=disable". The database's tables are dropped
// and recreated by every test.
const postgresDSNEnv = "AUTHGORM_TEST_POSTGRES_DSN"

// backend opens a fresh, migrated database for one test.
type backend struct {
	name string
	open func(t *testing.T) *gorm.DB
}

func backends() []backend {
	b := []backend{{name: "sqlite", open: openSQLite}}
	if os.Getenv(postgresDSNEnv) != "" {
		b = append(b, backend{name: "postgres", open: openPostgres})
	}
	return b
}

// forEachBackend runs fn as a subtest against every available backend.
func forEachBackend(t *testing.T, fn func(t *testing.T, s *Store, db *gorm.DB)) {
	t.Helper()
	for _, b := range backends() {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			s := New(db)
			if err := s.Migrate(context.Background()); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			fn(t, s, db)
		})
	}
}

// gormConfig returns a new config for each connection. A *gorm.Config must
// not be shared between dialects: gorm.Open stores the dialect's clause
// builders in it, and SQLite's would strip FOR UPDATE from PostgreSQL queries.
func gormConfig() *gorm.Config { return &gorm.Config{Logger: logger.Discard} }

func openSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	dsn := "file:" + path + "?_txlock=immediate&_busy_timeout=10000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), gormConfig())
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	t.Cleanup(func() { closeDB(t, db) })
	return db
}

func openPostgres(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(os.Getenv(postgresDSNEnv)), gormConfig())
	if err != nil {
		t.Fatalf("opening postgres: %v", err)
	}
	if err := db.Migrator().DropTable(allModels()...); err != nil {
		t.Fatalf("dropping tables: %v", err)
	}
	t.Cleanup(func() { closeDB(t, db) })
	return db
}

func allModels() []any {
	return []any{&User{}, &SigningKey{}, &RefreshFamily{}, &RefreshToken{}, &RefreshSubject{}}
}

func closeDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Errorf("getting sql.DB: %v", err)
		return
	}
	_ = sqlDB.Close() // tests that close the DB themselves make this fail
}

// brokenStore returns a migrated store whose connection is closed, so every
// query fails.
func brokenStore(t *testing.T) *Store {
	t.Helper()
	db := openSQLite(t)
	s := New(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	closeDB(t, db)
	return s
}

func newKey(t *testing.T, createdAt, expiresAt time.Time) *auth.VerificationKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return &auth.VerificationKey{ID: uuid.New(), PublicKey: &priv.PublicKey, CreatedAt: createdAt, ExpiresAt: expiresAt}
}

// baseTime is a fixed instant with microsecond precision, which every
// backend stores exactly.
var baseTime = time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)

// loginRecord returns the first record of a new family.
func loginRecord(subject string, issuedAt time.Time, ttl time.Duration) auth.RefreshTokenRecord {
	return auth.RefreshTokenRecord{
		ID:        uuid.New(),
		FamilyID:  uuid.New(),
		Subject:   subject,
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(ttl),
	}
}

// childRecord returns a record that replaces parent in its family.
func childRecord(parent auth.RefreshTokenRecord, issuedAt time.Time, ttl time.Duration) auth.RefreshTokenRecord {
	return auth.RefreshTokenRecord{
		ID:        uuid.New(),
		ParentID:  parent.ID,
		FamilyID:  parent.FamilyID,
		Subject:   parent.Subject,
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(ttl),
	}
}

func mustCreate(t *testing.T, s *Store, rec auth.RefreshTokenRecord) {
	t.Helper()
	if err := s.CreateRefreshToken(context.Background(), rec); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
}

func countRows(t *testing.T, db *gorm.DB, model any) int64 {
	t.Helper()
	var n int64
	if err := db.Model(model).Count(&n).Error; err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	return n
}
