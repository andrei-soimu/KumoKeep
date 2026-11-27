// Package auth handles users, passwords, sessions and invites.
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/andrei-soimu/KumoKeep/server/internal/db"
	"github.com/andrei-soimu/KumoKeep/server/internal/db/store"
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"

	// SessionTTL is the sliding lifetime of a web session.
	SessionTTL = 30 * 24 * time.Hour
	// touchInterval limits session last-seen writes to one per interval.
	touchInterval = time.Hour
	// MaxInviteTTL bounds how long an invite link may stay valid.
	MaxInviteTTL = 30 * 24 * time.Hour
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUnauthenticated    = errors.New("not authenticated")
	ErrInvalidInvite      = errors.New("invite is invalid or expired")
	ErrUserExists         = errors.New("username or email already in use")
	ErrInvalidUsername    = errors.New("username must be 3-32 characters: lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")
	ErrInvalidEmail       = errors.New("invalid email address")
	ErrInvalidRole        = errors.New("role must be 'admin' or 'user'")
	ErrInviteEmail        = errors.New("this invite is for a different email address")
)

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

type Service struct {
	db  *sql.DB
	q   *store.Queries
	log *slog.Logger
	now func() time.Time

	dummyOnce sync.Once
	dummyHash string
}

func NewService(database *sql.DB, log *slog.Logger) *Service {
	return &Service{db: database, q: store.New(database), log: log, now: time.Now}
}

// ClientMeta describes the client making a request, for sessions and the audit log.
type ClientMeta struct {
	IP        string
	UserAgent string
}

type NewUser struct {
	Username string
	Email    string
	Password string
	Role     string
}

func (n *NewUser) normalize() error {
	n.Username = strings.ToLower(strings.TrimSpace(n.Username))
	n.Email = strings.TrimSpace(n.Email)
	if !usernameRe.MatchString(n.Username) {
		return ErrInvalidUsername
	}
	if a, err := mail.ParseAddress(n.Email); err != nil || a.Address != n.Email || a.Name != "" {
		return ErrInvalidEmail
	}
	if n.Role != RoleAdmin && n.Role != RoleUser {
		return ErrInvalidRole
	}
	return ValidateNewPassword(n.Password)
}

// CreateUser validates and inserts a user. Used by the admin CLI and registration.
func (s *Service) CreateUser(ctx context.Context, n NewUser) (store.User, error) {
	hash, err := prepareUser(&n)
	if err != nil {
		return store.User{}, err
	}
	return s.insertUser(ctx, s.q, n, hash)
}

// prepareUser validates n and hashes its password. It is kept separate from
// insertUser so the slow hash never runs while holding a write transaction.
func prepareUser(n *NewUser) (string, error) {
	if err := n.normalize(); err != nil {
		return "", err
	}
	return HashPassword(n.Password)
}

func (s *Service) insertUser(ctx context.Context, q *store.Queries, n NewUser, hash string) (store.User, error) {
	now := s.now().Unix()
	u, err := q.CreateUser(ctx, store.CreateUserParams{
		ID:           uuid.NewString(),
		Username:     n.Username,
		Email:        n.Email,
		PasswordHash: hash,
		Role:         n.Role,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if db.IsUniqueViolation(err) {
		return store.User{}, ErrUserExists
	}
	return u, err
}

// Login checks credentials and creates a web session, returning its token.
// Unknown users and wrong passwords take the same time and return the same error.
func (s *Service) Login(ctx context.Context, login, password string, meta ClientMeta) (string, store.User, error) {
	login = strings.TrimSpace(login)
	var (
		u   store.User
		err error
	)
	if strings.Contains(login, "@") {
		u, err = s.q.GetUserByEmail(ctx, login)
	} else {
		u, err = s.q.GetUserByUsername(ctx, strings.ToLower(login))
	}
	if errors.Is(err, sql.ErrNoRows) {
		_, _, _ = VerifyPassword(password, s.dummy()) // equalize timing
		s.Audit(ctx, "", "login.failed", meta, map[string]any{"login": login})
		return "", store.User{}, ErrInvalidCredentials
	}
	if err != nil {
		return "", store.User{}, err
	}

	ok, rehash, err := VerifyPassword(password, u.PasswordHash)
	if err != nil {
		return "", store.User{}, err
	}
	if !ok || u.DisabledAt.Valid {
		s.Audit(ctx, u.ID, "login.failed", meta, nil)
		return "", store.User{}, ErrInvalidCredentials
	}
	if rehash {
		if h, err := HashPassword(password); err == nil {
			if err := s.q.UpdateUserPasswordHash(ctx, store.UpdateUserPasswordHashParams{
				PasswordHash: h, UpdatedAt: s.now().Unix(), ID: u.ID,
			}); err != nil {
				s.log.Warn("password rehash failed", "user", u.ID, "err", err)
			}
		}
	}

	token, err := s.createSession(ctx, s.q, u.ID, meta)
	if err != nil {
		return "", store.User{}, err
	}
	s.Audit(ctx, u.ID, "login.success", meta, nil)
	return token, u, nil
}

func (s *Service) createSession(ctx context.Context, q *store.Queries, userID string, meta ClientMeta) (string, error) {
	token, hash, err := NewToken()
	if err != nil {
		return "", err
	}
	now := s.now()
	err = q.CreateSession(ctx, store.CreateSessionParams{
		TokenHash:  hash,
		UserID:     userID,
		CreatedAt:  now.Unix(),
		LastSeenAt: now.Unix(),
		ExpiresAt:  now.Add(SessionTTL).Unix(),
		UserAgent:  truncate(meta.UserAgent, 256),
		IP:         meta.IP,
	})
	return token, err
}

// Authenticate resolves a session token to its user and extends the session.
func (s *Service) Authenticate(ctx context.Context, token string) (store.User, error) {
	if token == "" {
		return store.User{}, ErrUnauthenticated
	}
	hash := HashToken(token)
	now := s.now()
	row, err := s.q.GetSessionWithUser(ctx, store.GetSessionWithUserParams{TokenHash: hash, ExpiresAt: now.Unix()})
	if errors.Is(err, sql.ErrNoRows) {
		return store.User{}, ErrUnauthenticated
	}
	if err != nil {
		return store.User{}, err
	}
	if row.User.DisabledAt.Valid {
		return store.User{}, ErrUnauthenticated
	}
	if now.Unix()-row.Session.LastSeenAt >= int64(touchInterval/time.Second) {
		if err := s.q.TouchSession(ctx, store.TouchSessionParams{
			LastSeenAt: now.Unix(), ExpiresAt: now.Add(SessionTTL).Unix(), TokenHash: hash,
		}); err != nil {
			s.log.Warn("touch session failed", "err", err)
		}
	}
	return row.User, nil
}

// Logout deletes the session for token.
func (s *Service) Logout(ctx context.Context, token string) error {
	return s.q.DeleteSession(ctx, HashToken(token))
}

// CleanupExpiredSessions removes expired sessions and returns how many.
func (s *Service) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	return s.q.DeleteExpiredSessions(ctx, s.now().Unix())
}

// CreateInvite creates a one-time registration link token. email may be empty
// to allow any address.
func (s *Service) CreateInvite(ctx context.Context, createdBy store.User, email, role string, ttl time.Duration, meta ClientMeta) (string, time.Time, error) {
	if role != RoleAdmin && role != RoleUser {
		return "", time.Time{}, ErrInvalidRole
	}
	email = strings.TrimSpace(email)
	if email != "" {
		if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
			return "", time.Time{}, ErrInvalidEmail
		}
	}
	if ttl <= 0 || ttl > MaxInviteTTL {
		ttl = 7 * 24 * time.Hour
	}
	token, hash, err := NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	expires := now.Add(ttl)
	err = s.q.CreateInvite(ctx, store.CreateInviteParams{
		TokenHash: hash,
		CreatedBy: createdBy.ID,
		Email:     sql.NullString{String: email, Valid: email != ""},
		Role:      role,
		CreatedAt: now.Unix(),
		ExpiresAt: expires.Unix(),
	})
	if err != nil {
		return "", time.Time{}, err
	}
	s.Audit(ctx, createdBy.ID, "invite.created", meta, map[string]any{"role": role, "email": email})
	return token, expires, nil
}

// Register creates a user from an invite and logs them in, atomically.
func (s *Service) Register(ctx context.Context, inviteToken string, n NewUser, meta ClientMeta) (string, store.User, error) {
	n.Role = RoleUser // validated placeholder; the real role comes from the invite
	pwHash, err := prepareUser(&n)
	if err != nil {
		return "", store.User{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", store.User{}, err
	}
	defer tx.Rollback()
	q := s.q.WithTx(tx)

	hash := HashToken(inviteToken)
	now := s.now().Unix()
	inv, err := q.GetValidInvite(ctx, store.GetValidInviteParams{TokenHash: hash, ExpiresAt: now})
	if errors.Is(err, sql.ErrNoRows) {
		return "", store.User{}, ErrInvalidInvite
	}
	if err != nil {
		return "", store.User{}, err
	}
	if inv.Email.Valid && !strings.EqualFold(inv.Email.String, n.Email) {
		return "", store.User{}, ErrInviteEmail
	}

	n.Role = inv.Role
	u, err := s.insertUser(ctx, q, n, pwHash)
	if err != nil {
		return "", store.User{}, err
	}
	used, err := q.MarkInviteUsed(ctx, store.MarkInviteUsedParams{
		UsedAt:    sql.NullInt64{Int64: now, Valid: true},
		UsedBy:    sql.NullString{String: u.ID, Valid: true},
		TokenHash: hash,
	})
	if err != nil {
		return "", store.User{}, err
	}
	if used != 1 {
		return "", store.User{}, ErrInvalidInvite
	}
	token, err := s.createSession(ctx, q, u.ID, meta)
	if err != nil {
		return "", store.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", store.User{}, err
	}
	s.Audit(ctx, u.ID, "user.registered", meta, nil)
	return token, u, nil
}

// Audit records a security event. Failures are logged, never returned:
// auditing must not break the action being audited.
func (s *Service) Audit(ctx context.Context, userID, event string, meta ClientMeta, detail map[string]any) {
	d := []byte("{}")
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			d = b
		}
	}
	err := s.q.InsertAuditEvent(ctx, store.InsertAuditEventParams{
		UserID:    sql.NullString{String: userID, Valid: userID != ""},
		Event:     event,
		IP:        meta.IP,
		Detail:    string(d),
		CreatedAt: s.now().Unix(),
	})
	if err != nil {
		s.log.Error("audit write failed", "event", event, "err", err)
	}
}

func (s *Service) dummy() string {
	s.dummyOnce.Do(func() {
		h, err := HashPassword("kumokeep-dummy-password-for-timing")
		if err != nil {
			panic(fmt.Sprintf("dummy hash: %v", err))
		}
		s.dummyHash = h
	})
	return s.dummyHash
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
