-- Foundation: users, web sessions, invites, audit log.
-- Timestamps are Unix seconds (UTC). Token columns store SHA-256 hashes, never raw tokens.

-- +goose Up
CREATE TABLE users (
    id            TEXT    NOT NULL PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('admin', 'user')),
    quota_bytes   INTEGER,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    disabled_at   INTEGER
) STRICT;

CREATE TABLE sessions (
    token_hash   BLOB    NOT NULL PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    user_agent   TEXT    NOT NULL,
    ip           TEXT    NOT NULL
) STRICT;

CREATE INDEX sessions_user_id ON sessions (user_id);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

CREATE TABLE invites (
    token_hash BLOB    NOT NULL PRIMARY KEY,
    created_by TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email      TEXT COLLATE NOCASE,
    role       TEXT    NOT NULL CHECK (role IN ('admin', 'user')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    used_by    TEXT REFERENCES users (id) ON DELETE SET NULL
) STRICT;

CREATE TABLE audit_log (
    id         INTEGER NOT NULL PRIMARY KEY,
    user_id    TEXT REFERENCES users (id) ON DELETE SET NULL,
    event      TEXT    NOT NULL,
    ip         TEXT    NOT NULL,
    detail     TEXT    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX audit_log_user_id ON audit_log (user_id, created_at);

-- +goose Down
DROP TABLE audit_log;
DROP TABLE invites;
DROP TABLE sessions;
DROP TABLE users;
