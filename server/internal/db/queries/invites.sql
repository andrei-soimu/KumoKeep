-- name: CreateInvite :exec
INSERT INTO invites (token_hash, created_by, email, role, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetValidInvite :one
SELECT * FROM invites
WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?;

-- name: MarkInviteUsed :execrows
UPDATE invites SET used_at = ?, used_by = ?
WHERE token_hash = ? AND used_at IS NULL;
