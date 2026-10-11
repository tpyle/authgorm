package passkeygorm

import (
	"context"
	"sync"
	"time"

	"github.com/tpyle/auth/passkey"
	"gorm.io/gorm"
)

// Interface checks.
var (
	_ passkey.UserStore       = (*Store)(nil)
	_ passkey.CredentialStore = (*Store)(nil)
	_ passkey.CeremonyStore   = (*Store)(nil)
)

const (
	// defaultCeremonyPurgeInterval is the least time between the purges
	// SaveCeremony runs.
	defaultCeremonyPurgeInterval = time.Minute
	// defaultPurgeBatchSize is how many ceremonies each purge statement
	// deletes.
	defaultPurgeBatchSize = 1000
	// ceremonyPurgeTimeout bounds how long SaveCeremony's purge can delay
	// the request it runs in.
	ceremonyPurgeTimeout = 5 * time.Second
)

// Store implements the passkey store interfaces on one GORM connection. It
// is safe for concurrent use.
type Store struct {
	db             *gorm.DB
	now            func() time.Time
	purgeInterval  time.Duration
	purgeBatchSize int

	mu        sync.Mutex
	lastPurge time.Time // when SaveCeremony last purged
}

// Option configures a [Store].
type Option func(*Store)

// WithCeremonyPurgeInterval sets the least time between the purges of
// expired ceremonies that [Store.SaveCeremony] runs. The default is one
// minute. Zero or a negative value disables them; then call
// [Store.PurgeExpiredCeremonies] yourself.
func WithCeremonyPurgeInterval(d time.Duration) Option {
	return func(s *Store) { s.purgeInterval = d }
}

// WithClock overrides the time source used to decide which ceremonies
// [Store.SaveCeremony] purges. Defaults to [time.Now]. Pass the same clock
// given to passkey.WithClock, so ceremonies are not purged before the
// passkey service considers them expired.
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// New returns a Store that uses db for every operation. Each call passes its
// context on to db.
func New(db *gorm.DB, opts ...Option) *Store {
	s := &Store{
		db:             db,
		now:            time.Now,
		purgeInterval:  defaultCeremonyPurgeInterval,
		purgeBatchSize: defaultPurgeBatchSize,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Migrate creates or updates the tables the store uses (see [User],
// [Credential] and [Ceremony]). It is safe to call on every start.
func (s *Store) Migrate(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(&User{}, &Credential{}, &Ceremony{})
}

// Options returns the passkey options that make a passkey service use s as
// its user, credential and ceremony store. Append the other options, such as
// passkey.WithRelyingParty and passkey.WithTokenIssuer, to the result.
func (s *Store) Options() []passkey.Option {
	return []passkey.Option{
		passkey.WithUserStore(s),
		passkey.WithCredentialStore(s),
		passkey.WithCeremonyStore(s),
	}
}

// User is a row of the "auth_passkey_users" table: a user's WebAuthn
// identity.
type User struct {
	// Subject is the username, as used by the auth package.
	Subject string `gorm:"primaryKey;size:255"`
	// Handle is the WebAuthn user handle, made by passkey.NewUserHandle.
	Handle []byte `gorm:"size:64;not null;uniqueIndex"`
	// Name is the account name shown by authenticators.
	Name string `gorm:"not null"`
	// DisplayName is a friendlier name. Empty means Name.
	DisplayName string `gorm:"not null;default:''"`
	// CreatedAt is when the row was created.
	CreatedAt time.Time `gorm:"not null"`
}

// TableName implements GORM's tabler interface.
func (User) TableName() string { return "auth_passkey_users" }

// Credential is a row of the "auth_passkey_credentials" table: one
// registered credential. The columns mirror [passkey.Credential].
type Credential struct {
	// ID is the credential ID chosen by the authenticator.
	ID []byte `gorm:"primaryKey;size:1023"`
	// Subject is the user the credential belongs to.
	Subject string `gorm:"size:255;not null;index"`
	// PublicKey is the COSE-encoded public key.
	PublicKey []byte `gorm:"not null"`
	// SignCount is the highest signature counter seen. It holds a uint32,
	// stored as int64 because not every database has unsigned columns.
	SignCount int64 `gorm:"not null"`
	// AAGUID identifies the authenticator model.
	AAGUID []byte `gorm:"size:16"`
	// Transports is stored as a JSON array of strings.
	Transports        []string `gorm:"serializer:json"`
	AttestationType   string   `gorm:"not null;default:''"`
	AttestationFormat string   `gorm:"not null;default:''"`
	UserVerified      bool     `gorm:"not null"`
	BackupEligible    bool     `gorm:"not null"`
	BackupState       bool     `gorm:"not null"`
	// CloneWarning, once set, is never cleared by the store.
	CloneWarning bool `gorm:"not null;default:false"`
	// Label is the user-facing name of the credential.
	Label string `gorm:"not null;default:''"`
	// CreatedAt is when the credential was registered.
	CreatedAt time.Time `gorm:"not null;autoCreateTime:false"`
	// LastUsedAt is when the credential last logged in. NULL means never.
	LastUsedAt *time.Time
}

// TableName implements GORM's tabler interface.
func (Credential) TableName() string { return "auth_passkey_credentials" }

// Ceremony is a row of the "auth_passkey_ceremonies" table: the state of
// one registration or login between its Begin and Finish steps.
type Ceremony struct {
	// ID is the ceremony's UUID.
	ID string `gorm:"primaryKey;size:36"`
	// Data is opaque to the store.
	Data []byte `gorm:"not null"`
	// ExpiresAt is when the ceremony can no longer be finished.
	ExpiresAt time.Time `gorm:"not null;index"`
}

// TableName implements GORM's tabler interface.
func (Ceremony) TableName() string { return "auth_passkey_ceremonies" }
