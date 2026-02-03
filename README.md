# authgorm

A GORM-based storage implementation for the [`github.com/tpyle/auth`](https://github.com/tpyle/auth) authentication library. This package provides persistent storage for users, signing keys, and refresh tokens using GORM as the ORM layer.

## Overview

`authgorm` implements the storage interfaces required by the `auth` package, allowing you to store authentication data in any database supported by GORM (PostgreSQL, MySQL, SQLite, SQL Server, etc.).

## Features

- **User Management**: Store and retrieve users with hashed passwords
- **Signing Key Management**: Persist ECDSA signing keys for JWT token signing
- **Refresh Token Storage**: Manage long-lived refresh tokens with proper user associations
- **Flexible Database Support**: Works with any GORM-supported database
- **Automatic Migrations**: Built-in database schema migration support
- **Clean Integration**: Seamlessly integrates with the `auth` package via options pattern

## Installation

```bash
go get github.com/tpyle/authgorm
```

## Quick Start

```go
package main

import (
    "github.com/tpyle/auth"
    "github.com/tpyle/authgorm"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

func main() {
    // Setup database connection
    db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
    if err != nil {
        panic(err)
    }

    // Create AuthGorm instance
    ag := authgorm.NewAuthGorm(db)

    // Run migrations
    if err := ag.Migrate(); err != nil {
        panic(err)
    }

    // Create auth system with GORM storage
    authSystem := auth.Create(
        ag.AsOptions(), // Wire up AuthGorm as the storage backend
        // ... other auth options
    )
    if err != nil {
        panic(err)
    }

    // Use authSystem for authentication...
    _ = authSystem
}
```

## Database Schema

The library manages three main tables:

### Users
- **user_subject**: Unique identifier (email, username, etc.)
- **hashed_password**: Bcrypt or other hashed password

### SigningKeys
- **key_id**: Unique key identifier (UUID)
- **public_key**: Binary representation of ECDSA public key
- **creation_time**: Unix timestamp of key creation

### RefreshTokens
- **token_id**: Unique token identifier (UUID)
- **user_id**: Foreign key to users table
- **random**: Cryptographically random bytes for verification

All tables include standard GORM fields (`ID`, `CreatedAt`, `UpdatedAt`, `DeletedAt`).

## API Reference

### Core Functions

#### `NewAuthGorm(dbConnection *gorm.DB) *AuthGorm`
Creates a new AuthGorm instance with the given database connection.

#### `Migrate() error`
Runs auto-migration for all authentication-related tables.

#### `AsOptions() auth.Option`
Returns an auth.Option that configures the auth system to use this AuthGorm instance.

### Signing Key Operations

#### `StoreNewSigningKey(kp *auth.KeyPairWithCreationTime) error`
Stores a new ECDSA signing key in the database.

#### `GetSigningKeyByID(keyID uuid.UUID) (*auth.KeyPairWithCreationTime, error)`
Retrieves a signing key by its ID.

#### `DeleteSigningKeysByIDs(keyIDs []uuid.UUID) error`
Deletes multiple signing keys by their IDs. Returns `ErrNotAllKeysDeleted` if not all keys were deleted.

### User Operations

#### `GetPasswordForUserSubject(userSubject string) (string, error)`
Retrieves the hashed password for a user by their subject identifier.

### Refresh Token Operations

#### `StoreNewRefreshToken(rt *auth.RefreshToken) error`
Stores a new refresh token in the database.

#### `GetRefreshTokenByID(tokenID uuid.UUID) (*auth.RefreshToken, error)`
Retrieves a refresh token by its ID.

#### `DeleteRefreshTokenByID(tokenID uuid.UUID) error`
Deletes a refresh token by its ID (used for logout/revocation).

## Error Handling

The library provides the following sentinel errors:

- **`ErrNotAllKeysDeleted`**: Returned when a delete operation fails to delete all requested signing keys

## Database Support

AuthGorm works with any database supported by GORM:

- PostgreSQL
- MySQL
- SQLite
- SQL Server
- And more...

Simply provide the appropriate GORM database connection when creating the AuthGorm instance.

## Testing

The library includes comprehensive tests using SQLite in-memory databases:

```bash
go test ./...
```

## Dependencies

- [gorm.io/gorm](https://gorm.io/) - The ORM library
- [github.com/tpyle/auth](https://github.com/tpyle/auth) - The authentication library
- [github.com/google/uuid](https://github.com/google/uuid) - UUID support

## License

This project's license can be found in the LICENSE file.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
