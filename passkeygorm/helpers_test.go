package passkeygorm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// postgresDSNEnv names the environment variable that enables the PostgreSQL
// backend in tests. The database's tables are dropped and recreated by every
// test.
const postgresDSNEnv = "AUTHGORM_TEST_POSTGRES_DSN"

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

// forEachBackend runs fn as a subtest against every available backend, with
// a migrated store using clock.
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
// builders in it.
func gormConfig() *gorm.Config { return &gorm.Config{Logger: logger.Discard} }

// sqliteDSN returns a DSN for a new SQLite database file.
func sqliteDSN(t *testing.T) string {
	return "file:" + filepath.Join(t.TempDir(), "auth.db") + "?_txlock=immediate&_busy_timeout=10000&_journal_mode=WAL"
}

func openSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(sqliteDSN(t)), gormConfig())
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	t.Cleanup(func() { closeDB(db) })
	return db
}

func openPostgres(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(os.Getenv(postgresDSNEnv)), gormConfig())
	if err != nil {
		t.Fatalf("opening postgres: %v", err)
	}
	if err := db.Migrator().DropTable(allTables...); err != nil {
		t.Fatalf("dropping tables: %v", err)
	}
	t.Cleanup(func() { closeDB(db) })
	return db
}

// allTables lists every table the tests create, including authgorm's, so
// tests on a shared PostgreSQL database start from scratch.
var allTables = []any{
	&User{}, &Credential{}, &Ceremony{},
	"users", "auth_signing_keys", "auth_refresh_families", "auth_refresh_tokens", "auth_refresh_subjects",
}

func closeDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close() // tests that close the DB themselves make this fail
	}
}

// brokenStore returns a migrated store whose connection is closed, so every
// query fails.
func brokenStore(t *testing.T, opts ...Option) *Store {
	t.Helper()
	db := openSQLite(t)
	s := New(db, opts...)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	closeDB(db)
	return s
}

// baseTime is a fixed instant with microsecond precision, which every
// backend stores exactly.
var baseTime = time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)

// fakeClock is a settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func countRows(t *testing.T, db *gorm.DB, model any) int64 {
	t.Helper()
	var n int64
	if err := db.Model(model).Count(&n).Error; err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	return n
}

// failOn makes every op ("query", "create", "update" or "delete") on table
// fail. The returned function removes the failure.
func failOn(t *testing.T, db *gorm.DB, op, table string) (restore func()) {
	t.Helper()
	injected := errors.New("injected failure")
	fail := func(tx *gorm.DB) {
		if tx.Statement.Table == table {
			_ = tx.AddError(injected)
		}
	}
	name := "test:fail_" + op + "_" + table
	type processor interface {
		Remove(string) error
	}
	var p processor
	var err error
	switch op {
	case "query":
		cb := db.Callback().Query()
		err, p = cb.Before("gorm:query").Register(name, fail), cb
	case "create":
		cb := db.Callback().Create()
		err, p = cb.Before("gorm:create").Register(name, fail), cb
	case "update":
		cb := db.Callback().Update()
		err, p = cb.Before("gorm:update").Register(name, fail), cb
	case "delete":
		cb := db.Callback().Delete()
		err, p = cb.Before("gorm:delete").Register(name, fail), cb
	default:
		t.Fatalf("unknown op %q", op)
	}
	if err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := p.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
}
