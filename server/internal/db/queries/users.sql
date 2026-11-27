-- name: CreateUser :one
INSERT INTO users (id, username, email, password_hash, role, quota_bytes, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ?;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = ?;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: UpdateUserPasswordHash :exec
UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?;
