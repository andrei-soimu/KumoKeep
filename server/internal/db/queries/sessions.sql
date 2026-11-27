-- name: CreateSession :exec
INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, user_agent, ip)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetSessionWithUser :one
SELECT sqlc.embed(sessions), sqlc.embed(users)
FROM sessions
JOIN users ON users.id = sessions.user_id
WHERE sessions.token_hash = ? AND sessions.expires_at > ?;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE token_hash = ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE token_hash = ?;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = ?;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at <= ?;
