// Package db opens the SQLite database and applies migrations.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"

	"github.com/pressly/goose/v3"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open opens (creating if needed) the SQLite database at path with settings
// suited to a single-process server: WAL journal, foreign keys on, and
// IMMEDIATE transactions so writers queue on busy_timeout instead of failing.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(8)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	return db, nil
}

// Migrate applies all pending migrations embedded in the binary.
func Migrate(ctx context.Context, db *sql.DB) error {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	return nil
}

// IsUniqueViolation reports whether err is a UNIQUE or PRIMARY KEY constraint failure.
func IsUniqueViolation(err error) bool {
	var e *sqlite.Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || e.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}
