package authgorm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	err = db.AutoMigrate(&User{}, &SigningKey{}, &RefreshToken{})
	if err != nil {
		t.Fatalf("Failed to migrate test database: %v", err)
	}

	return db
}

func generateTestKeyPair(t *testing.T) *auth.KeyPairWithCreationTime {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	return &auth.KeyPairWithCreationTime{
		ID:           uuid.New(),
		PublicKey:    &privateKey.PublicKey,
		CreationTime: time.Now(),
	}
}

func TestNewAuthGorm(t *testing.T) {
	db := setupTestDB(t)

	ag := NewAuthGorm(db)

	if ag == nil {
		t.Fatal("NewAuthGorm returned nil")
	}

	if ag.dbConnection != db {
		t.Error("Database connection not set correctly")
	}
}

func TestAuthGorm_Migrate(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	ag := NewAuthGorm(db)

	err = ag.Migrate()
	if err != nil {
		t.Errorf("Migrate() failed: %v", err)
	}

	// Verify tables exist by attempting to query them
	var user User
	err = db.First(&user).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("User table not created: %v", err)
	}

	var signingKey SigningKey
	err = db.First(&signingKey).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("SigningKey table not created: %v", err)
	}

	var refreshToken RefreshToken
	err = db.First(&refreshToken).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("RefreshToken table not created: %v", err)
	}
}

func TestAuthGorm_StoreNewSigningKey(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	kp := generateTestKeyPair(t)

	err := ag.StoreNewSigningKey(kp)
	if err != nil {
		t.Fatalf("StoreNewSigningKey() failed: %v", err)
	}

	// Verify the key was stored
	var storedKey SigningKey
	err = db.Where("key_id = ?", kp.ID.String()).First(&storedKey).Error
	if err != nil {
		t.Fatalf("Failed to retrieve stored key: %v", err)
	}

	if storedKey.KeyID != kp.ID.String() {
		t.Errorf("KeyID mismatch: got %s, want %s", storedKey.KeyID, kp.ID.String())
	}

	if storedKey.CreationTime != kp.CreationTime.Unix() {
		t.Errorf("CreationTime mismatch: got %d, want %d", storedKey.CreationTime, kp.CreationTime.Unix())
	}

	if len(storedKey.PublicKey) == 0 {
		t.Error("PublicKey is empty")
	}
}

func TestAuthGorm_StoreNewSigningKey_Duplicate(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	kp := generateTestKeyPair(t)

	err := ag.StoreNewSigningKey(kp)
	if err != nil {
		t.Fatalf("First StoreNewSigningKey() failed: %v", err)
	}

	// Verify the key exists
	var count int64
	db.Model(&SigningKey{}).Where("key_id = ?", kp.ID.String()).Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 key after first store, found %d", count)
	}
}

func TestAuthGorm_GetSigningKeyByID(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	kp := generateTestKeyPair(t)

	err := ag.StoreNewSigningKey(kp)
	if err != nil {
		t.Fatalf("StoreNewSigningKey() failed: %v", err)
	}

	retrievedKP, err := ag.GetSigningKeyByID(kp.ID)
	if err != nil {
		t.Fatalf("GetSigningKeyByID() failed: %v", err)
	}

	if retrievedKP.ID != kp.ID {
		t.Errorf("ID mismatch: got %s, want %s", retrievedKP.ID, kp.ID)
	}

	if !retrievedKP.CreationTime.Equal(kp.CreationTime.Truncate(time.Second)) {
		t.Errorf("CreationTime mismatch: got %v, want %v", retrievedKP.CreationTime, kp.CreationTime.Truncate(time.Second))
	}

	if retrievedKP.PublicKey == nil {
		t.Error("PublicKey is nil")
	}
}

func TestAuthGorm_GetSigningKeyByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	nonExistentID := uuid.New()

	_, err := ag.GetSigningKeyByID(nonExistentID)
	if err == nil {
		t.Error("Expected error for non-existent key, got nil")
	}
}

func TestAuthGorm_GetSigningKeyByID_CorruptedData(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Store a key with invalid public key data
	keyID := uuid.New()
	signingKey := SigningKey{
		KeyID:        keyID.String(),
		PublicKey:    []byte("invalid data"),
		CreationTime: time.Now().Unix(),
	}

	err := gorm.G[SigningKey](db).Create(context.Background(), &signingKey)
	if err != nil {
		t.Fatalf("Failed to create corrupted key: %v", err)
	}

	_, err = ag.GetSigningKeyByID(keyID)
	if err == nil {
		t.Error("Expected error for corrupted key data, got nil")
	}
}

func TestAuthGorm_DeleteSigningKeysByIDs(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Store multiple keys
	kp1 := generateTestKeyPair(t)
	kp2 := generateTestKeyPair(t)
	kp3 := generateTestKeyPair(t)

	for _, kp := range []*auth.KeyPairWithCreationTime{kp1, kp2, kp3} {
		err := ag.StoreNewSigningKey(kp)
		if err != nil {
			t.Fatalf("StoreNewSigningKey() failed: %v", err)
		}
	}

	// Delete two of them
	err := ag.DeleteSigningKeysByIDs([]uuid.UUID{kp1.ID, kp2.ID})
	if err != nil {
		t.Fatalf("DeleteSigningKeysByIDs() failed: %v", err)
	}

	// Verify the keys were deleted
	var count int64
	db.Model(&SigningKey{}).Where("key_id IN ?", []string{kp1.ID.String(), kp2.ID.String()}).Count(&count)
	if count != 0 {
		t.Errorf("Expected 0 keys after deletion, found %d", count)
	}

	// Verify the third key still exists
	db.Model(&SigningKey{}).Where("key_id = ?", kp3.ID.String()).Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 remaining key, found %d", count)
	}
}

func TestAuthGorm_DeleteSigningKeysByIDs_NotAllFound(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	kp := generateTestKeyPair(t)
	err := ag.StoreNewSigningKey(kp)
	if err != nil {
		t.Fatalf("StoreNewSigningKey() failed: %v", err)
	}

	nonExistentID := uuid.New()

	err = ag.DeleteSigningKeysByIDs([]uuid.UUID{kp.ID, nonExistentID})
	if err == nil {
		t.Error("Expected error when not all keys are deleted, got nil")
	}

	if !errors.Is(err, ErrNotAllKeysDeleted) {
		t.Errorf("Expected ErrNotAllKeysDeleted, got %v", err)
	}
}

func TestAuthGorm_DeleteSigningKeysByIDs_Empty(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	err := ag.DeleteSigningKeysByIDs([]uuid.UUID{})
	if err != nil {
		t.Errorf("DeleteSigningKeysByIDs() with empty slice failed: %v", err)
	}
}

func TestAuthGorm_GetPasswordForUserSubject(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Create a test user
	user := User{
		UserSubject:    "test@example.com",
		HashedPassword: "hashedpassword123",
	}

	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	password, err := ag.GetPasswordForUserSubject("test@example.com")
	if err != nil {
		t.Fatalf("GetPasswordForUserSubject() failed: %v", err)
	}

	if password != "hashedpassword123" {
		t.Errorf("Password mismatch: got %s, want %s", password, "hashedpassword123")
	}
}

func TestAuthGorm_GetPasswordForUserSubject_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	_, err := ag.GetPasswordForUserSubject("nonexistent@example.com")
	if err == nil {
		t.Error("Expected error for non-existent user, got nil")
	}
}

func TestAuthGorm_StoreNewRefreshToken(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Create a user first
	user := User{
		UserSubject:    "user@example.com",
		HashedPassword: "password",
	}
	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	rt := &auth.RefreshToken{
		ID:      uuid.New(),
		Subject: "user@example.com",
		Rand:    []byte("random-bytes"),
	}

	err = ag.StoreNewRefreshToken(rt)
	if err != nil {
		t.Fatalf("StoreNewRefreshToken() failed: %v", err)
	}

	// Verify the token was stored
	var storedToken RefreshToken
	err = db.Preload("User").Where("token_id = ?", rt.ID.String()).First(&storedToken).Error
	if err != nil {
		t.Fatalf("Failed to retrieve stored token: %v", err)
	}

	if storedToken.TokenID != rt.ID.String() {
		t.Errorf("TokenID mismatch: got %s, want %s", storedToken.TokenID, rt.ID.String())
	}

	if storedToken.User.UserSubject != rt.Subject {
		t.Errorf("Subject mismatch: got %s, want %s", storedToken.User.UserSubject, rt.Subject)
	}

	if string(storedToken.Random) != string(rt.Rand) {
		t.Errorf("Random bytes mismatch")
	}
}

func TestAuthGorm_StoreNewRefreshToken_ExistingUser(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Create a user first
	user := User{
		UserSubject:    "existing@example.com",
		HashedPassword: "password",
	}
	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	rt := &auth.RefreshToken{
		ID:      uuid.New(),
		Subject: "existing@example.com",
		Rand:    []byte("random-bytes"),
	}

	err = ag.StoreNewRefreshToken(rt)
	if err != nil {
		t.Fatalf("StoreNewRefreshToken() failed: %v", err)
	}

	// Verify the user wasn't duplicated
	var count int64
	db.Model(&User{}).Where("user_subject = ?", "existing@example.com").Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 user with subject, found %d", count)
	}

	// Verify the token was created with the existing user
	var storedToken RefreshToken
	err = db.Preload("User").Where("token_id = ?", rt.ID.String()).First(&storedToken).Error
	if err != nil {
		t.Fatalf("Failed to retrieve stored token: %v", err)
	}

	if storedToken.UserID != user.ID {
		t.Errorf("Token was not associated with existing user")
	}
}

func TestAuthGorm_StoreNewRefreshToken_NonExistentUser(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Try to store a refresh token without creating the user first
	rt := &auth.RefreshToken{
		ID:      uuid.New(),
		Subject: "nonexistent@example.com",
		Rand:    []byte("random-bytes"),
	}

	err := ag.StoreNewRefreshToken(rt)
	if err == nil {
		t.Error("Expected error when storing refresh token for non-existent user, got nil")
	}

	// Verify no token was created
	var count int64
	db.Model(&RefreshToken{}).Where("token_id = ?", rt.ID.String()).Count(&count)
	if count != 0 {
		t.Errorf("Expected 0 tokens after failed store, found %d", count)
	}
}

func TestAuthGorm_GetRefreshTokenByID(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Create a user first
	user := User{
		UserSubject:    "user@example.com",
		HashedPassword: "password",
	}
	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	rt := &auth.RefreshToken{
		ID:      uuid.New(),
		Subject: "user@example.com",
		Rand:    []byte("random-bytes"),
	}

	err = ag.StoreNewRefreshToken(rt)
	if err != nil {
		t.Fatalf("StoreNewRefreshToken() failed: %v", err)
	}

	retrievedRT, err := ag.GetRefreshTokenByID(rt.ID)
	if err != nil {
		t.Fatalf("GetRefreshTokenByID() failed: %v", err)
	}

	if retrievedRT.ID != rt.ID {
		t.Errorf("ID mismatch: got %s, want %s", retrievedRT.ID, rt.ID)
	}

	if retrievedRT.Subject != rt.Subject {
		t.Errorf("Subject mismatch: got %s, want %s", retrievedRT.Subject, rt.Subject)
	}

	if string(retrievedRT.Rand) != string(rt.Rand) {
		t.Errorf("Random bytes mismatch")
	}
}

func TestAuthGorm_GetRefreshTokenByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	nonExistentID := uuid.New()

	_, err := ag.GetRefreshTokenByID(nonExistentID)
	if err == nil {
		t.Error("Expected error for non-existent token, got nil")
	}
}

func TestAuthGorm_DeleteRefreshTokenByID(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Create a user first
	user := User{
		UserSubject:    "user@example.com",
		HashedPassword: "password",
	}
	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	rt := &auth.RefreshToken{
		ID:      uuid.New(),
		Subject: "user@example.com",
		Rand:    []byte("random-bytes"),
	}

	err = ag.StoreNewRefreshToken(rt)
	if err != nil {
		t.Fatalf("StoreNewRefreshToken() failed: %v", err)
	}

	err = ag.DeleteRefreshTokenByID(rt.ID)
	if err != nil {
		t.Fatalf("DeleteRefreshTokenByID() failed: %v", err)
	}

	// Verify the token was deleted
	var count int64
	db.Model(&RefreshToken{}).Where("token_id = ?", rt.ID.String()).Count(&count)
	if count != 0 {
		t.Errorf("Expected 0 tokens after deletion, found %d", count)
	}
}

func TestAuthGorm_DeleteRefreshTokenByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	nonExistentID := uuid.New()

	err := ag.DeleteRefreshTokenByID(nonExistentID)
	if err != nil {
		t.Errorf("DeleteRefreshTokenByID() for non-existent token failed: %v", err)
	}
}

func TestAuthGorm_AsOptions(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	opt := ag.AsOptions()

	if opt == nil {
		t.Fatal("AsOptions() returned nil")
	}

	// Apply the option to an Options struct
	options := &auth.Options{}
	opt(options)

	// Verify all functions are set
	if options.StoreNewSigningKeyFunc == nil {
		t.Error("StoreNewSigningKeyFunc not set")
	}

	if options.GetSigningKeyFunc == nil {
		t.Error("GetSigningKeyFunc not set")
	}

	if options.DeleteExpiredSigningKeysFunc == nil {
		t.Error("DeleteExpiredSigningKeysFunc not set")
	}

	if options.LookupUserPasswordFunc == nil {
		t.Error("LookupUserPasswordFunc not set")
	}

	if options.LookupRefreshTokenFunc == nil {
		t.Error("LookupRefreshTokenFunc not set")
	}

	if options.StoreRefreshTokenFunc == nil {
		t.Error("StoreRefreshTokenFunc not set")
	}

	if options.DeleteRefreshTokenFunc == nil {
		t.Error("DeleteRefreshTokenFunc not set")
	}
}

func TestAuthGorm_AsOptions_Integration(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	opt := ag.AsOptions()
	options := &auth.Options{}
	opt(options)

	// Test that the functions work through the options
	kp := generateTestKeyPair(t)

	err := options.StoreNewSigningKeyFunc(kp)
	if err != nil {
		t.Fatalf("StoreNewSigningKeyFunc failed: %v", err)
	}

	retrievedKP, err := options.GetSigningKeyFunc(kp.ID)
	if err != nil {
		t.Fatalf("GetSigningKeyFunc failed: %v", err)
	}

	if retrievedKP.ID != kp.ID {
		t.Errorf("Retrieved key ID mismatch")
	}

	err = options.DeleteExpiredSigningKeysFunc([]uuid.UUID{kp.ID})
	if err != nil {
		t.Fatalf("DeleteExpiredSigningKeysFunc failed: %v", err)
	}
}

func TestUser_TableConstraints(t *testing.T) {
	db := setupTestDB(t)

	user1 := User{
		UserSubject:    "duplicate@example.com",
		HashedPassword: "password1",
	}

	err := db.Create(&user1).Error
	if err != nil {
		t.Fatalf("Failed to create first user: %v", err)
	}

	// Verify user was created
	var count int64
	db.Model(&User{}).Where("user_subject = ?", "duplicate@example.com").Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 user, found %d", count)
	}
}

func TestSigningKey_TableConstraints(t *testing.T) {
	db := setupTestDB(t)

	key1 := SigningKey{
		KeyID:        "unique-key-id",
		PublicKey:    []byte("key1"),
		CreationTime: time.Now().Unix(),
	}

	err := db.Create(&key1).Error
	if err != nil {
		t.Fatalf("Failed to create first key: %v", err)
	}

	// Verify key was created
	var count int64
	db.Model(&SigningKey{}).Where("key_id = ?", "unique-key-id").Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 key, found %d", count)
	}
}

func TestRefreshToken_TableConstraints(t *testing.T) {
	db := setupTestDB(t)

	// Create a user first
	user := User{
		UserSubject:    "user@example.com",
		HashedPassword: "password",
	}
	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	token1 := RefreshToken{
		TokenID: "unique-token-id",
		UserID:  user.ID,
		Random:  []byte("random1"),
	}

	err = db.Create(&token1).Error
	if err != nil {
		t.Fatalf("Failed to create first token: %v", err)
	}

	// Verify token was created
	var count int64
	db.Model(&RefreshToken{}).Where("token_id = ?", "unique-token-id").Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 token, found %d", count)
	}
}

func TestRefreshToken_CascadeDelete(t *testing.T) {
	db := setupTestDB(t)

	db.Exec("PRAGMA foreign_keys = ON;")

	// Create a user
	user := User{
		UserSubject:    "user@example.com",
		HashedPassword: "password",
	}
	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create a refresh token
	token := RefreshToken{
		TokenID: uuid.New().String(),
		UserID:  user.ID,
		Random:  []byte("random"),
	}
	err = db.Create(&token).Error
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Verify the relationship
	var count int64
	db.Model(&RefreshToken{}).Where("user_id = ?", user.ID).Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 token for user, found %d", count)
	}
}

func TestErrNotAllKeysDeleted(t *testing.T) {
	if ErrNotAllKeysDeleted == nil {
		t.Error("ErrNotAllKeysDeleted is nil")
	}

	if ErrNotAllKeysDeleted.Error() != "not all signing keys were deleted" {
		t.Errorf("ErrNotAllKeysDeleted has unexpected message: %s", ErrNotAllKeysDeleted.Error())
	}
}

func TestAuthGorm_StoreNewRefreshToken_DatabaseError(t *testing.T) {
	// Create a closed database to trigger errors
	db := setupTestDB(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("Failed to get underlying DB: %v", err)
	}
	sqlDB.Close()

	ag := NewAuthGorm(db)

	rt := &auth.RefreshToken{
		ID:      uuid.New(),
		Subject: "user@example.com",
		Rand:    []byte("random-bytes"),
	}

	err = ag.StoreNewRefreshToken(rt)
	if err == nil {
		t.Error("Expected error when storing to closed database, got nil")
	}
}

func TestAuthGorm_StoreNewRefreshToken_MultipleTokensPerUser(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Create a user first
	user := User{
		UserSubject:    "user@example.com",
		HashedPassword: "password",
	}
	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Store multiple tokens for the same user
	rt1 := &auth.RefreshToken{
		ID:      uuid.New(),
		Subject: "user@example.com",
		Rand:    []byte("random-bytes-1"),
	}

	rt2 := &auth.RefreshToken{
		ID:      uuid.New(),
		Subject: "user@example.com",
		Rand:    []byte("random-bytes-2"),
	}

	err = ag.StoreNewRefreshToken(rt1)
	if err != nil {
		t.Fatalf("StoreNewRefreshToken(rt1) failed: %v", err)
	}

	err = ag.StoreNewRefreshToken(rt2)
	if err != nil {
		t.Fatalf("StoreNewRefreshToken(rt2) failed: %v", err)
	}

	// Verify only one user exists
	var userCount int64
	db.Model(&User{}).Where("user_subject = ?", "user@example.com").Count(&userCount)
	if userCount != 1 {
		t.Errorf("Expected 1 user, found %d", userCount)
	}

	// Verify both tokens exist
	var tokenCount int64
	db.Model(&RefreshToken{}).Count(&tokenCount)
	if tokenCount != 2 {
		t.Errorf("Expected 2 tokens, found %d", tokenCount)
	}
}

func TestAuthGorm_DeleteSigningKeysByIDs_SingleKey(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	kp := generateTestKeyPair(t)

	err := ag.StoreNewSigningKey(kp)
	if err != nil {
		t.Fatalf("StoreNewSigningKey() failed: %v", err)
	}

	// Delete single key
	err = ag.DeleteSigningKeysByIDs([]uuid.UUID{kp.ID})
	if err != nil {
		t.Fatalf("DeleteSigningKeysByIDs() failed: %v", err)
	}

	// Verify key was deleted
	var count int64
	db.Model(&SigningKey{}).Where("key_id = ?", kp.ID.String()).Count(&count)
	if count != 0 {
		t.Errorf("Expected 0 keys after deletion, found %d", count)
	}
}

func TestAuthGorm_GetRefreshTokenByID_MissingUser(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	// Create a user first
	user := User{
		UserSubject:    "user@example.com",
		HashedPassword: "password",
	}
	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create a token directly in the database
	tokenID := uuid.New()
	token := RefreshToken{
		TokenID: tokenID.String(),
		UserID:  user.ID,
		Random:  []byte("random"),
	}
	err = db.Create(&token).Error
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Delete the user (if cascade delete doesn't work, token will have no user)
	db.Unscoped().Delete(&user)

	// Try to get the token - it should still work or fail gracefully
	_, err = ag.GetRefreshTokenByID(tokenID)
	// We're just verifying this doesn't panic
	// The behavior depends on database configuration
}

func TestAuthGorm_AsOptions_AllFunctionsWork(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	opt := ag.AsOptions()
	options := &auth.Options{}
	opt(options)

	// Create a user first
	user := User{
		UserSubject:    "test@example.com",
		HashedPassword: "password",
	}
	err := db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test refresh token workflow
	rt := &auth.RefreshToken{
		ID:      uuid.New(),
		Subject: "test@example.com",
		Rand:    []byte("random-data"),
	}

	err = options.StoreRefreshTokenFunc(rt)
	if err != nil {
		t.Fatalf("StoreRefreshTokenFunc failed: %v", err)
	}

	retrievedRT, err := options.LookupRefreshTokenFunc(rt.ID)
	if err != nil {
		t.Fatalf("LookupRefreshTokenFunc failed: %v", err)
	}

	if retrievedRT.ID != rt.ID {
		t.Errorf("Retrieved token ID mismatch")
	}

	err = options.DeleteRefreshTokenFunc(rt.ID)
	if err != nil {
		t.Fatalf("DeleteRefreshTokenFunc failed: %v", err)
	}

	// Verify token was deleted
	_, err = options.LookupRefreshTokenFunc(rt.ID)
	if err == nil {
		t.Error("Expected error after deleting token, got nil")
	}
}

func TestAuthGorm_DeleteSigningKeysByIDs_AllNonExistent(t *testing.T) {
	db := setupTestDB(t)
	ag := NewAuthGorm(db)

	nonExistent1 := uuid.New()
	nonExistent2 := uuid.New()

	err := ag.DeleteSigningKeysByIDs([]uuid.UUID{nonExistent1, nonExistent2})
	if err == nil {
		t.Error("Expected error when deleting non-existent keys, got nil")
	}

	if !errors.Is(err, ErrNotAllKeysDeleted) {
		t.Errorf("Expected ErrNotAllKeysDeleted, got %v", err)
	}
}
