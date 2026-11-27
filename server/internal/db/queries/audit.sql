-- name: InsertAuditEvent :exec
INSERT INTO audit_log (user_id, event, ip, detail, created_at)
VALUES (?, ?, ?, ?, ?);
