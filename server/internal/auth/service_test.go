package auth

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/andrei-soimu/KumoKeep/server/internal/db"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	return NewService(database, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

var meta = ClientMeta{IP: "192.0.2.1", UserAgent: "test"}

func TestLoginFlow(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t)

	u, err := s.CreateUser(ctx, NewUser{Username: "Alice", Email: "alice@example.com", Password: "a very good password", Role: RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" {
		t.Errorf("username not normalized: %q", u.Username)
	}

	if _, _, err := s.Login(ctx, "alice", "wrong password!!", meta); err != ErrInvalidCredentials {
		t.Fatalf("wrong password: %v", err)
	}
	if _, _, err := s.Login(ctx, "nobody", "a very good password", meta); err != ErrInvalidCredentials {
		t.Fatalf("unknown user: %v", err)
	}

	token, _, err := s.Login(ctx, "ALICE@example.com", "a very good password", meta)
	if err != nil {
		t.Fatalf("login by email: %v", err)
	}
	got, err := s.Authenticate(ctx, token)
	if err != nil || got.ID != u.ID {
		t.Fatalf("authenticate: %v %v", got.ID, err)
	}

	if err := s.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token); err != ErrUnauthenticated {
		t.Fatalf("after logout: %v", err)
	}
}

func TestDuplicateUser(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t)
	n := NewUser{Username: "bob", Email: "bob@example.com", Password: "a very good password", Role: RoleUser}
	if _, err := s.CreateUser(ctx, n); err != nil {
		t.Fatal(err)
	}
	n.Username = "BOB2"
	n.Email = "BOB@example.com"
	if _, err := s.CreateUser(ctx, n); err != ErrUserExists {
		t.Fatalf("duplicate email: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t)
	if _, err := s.CreateUser(ctx, NewUser{Username: "carol", Email: "carol@example.com", Password: "a very good password", Role: RoleUser}); err != nil {
		t.Fatal(err)
	}
	token, _, err := s.Login(ctx, "carol", "a very good password", meta)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Now().Add(SessionTTL + time.Minute) }
	if _, err := s.Authenticate(ctx, token); err != ErrUnauthenticated {
		t.Fatalf("expired session: %v", err)
	}
	if n, err := s.CleanupExpiredSessions(ctx); err != nil || n != 1 {
		t.Fatalf("cleanup: n=%d err=%v", n, err)
	}
}

func TestInviteRegistration(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t)
	admin, err := s.CreateUser(ctx, NewUser{Username: "admin", Email: "admin@example.com", Password: "a very good password", Role: RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}

	inv, _, err := s.CreateInvite(ctx, admin, "dave@example.com", RoleUser, 0, meta)
	if err != nil {
		t.Fatal(err)
	}

	wrongEmail := NewUser{Username: "eve", Email: "eve@example.com", Password: "a very good password"}
	if _, _, err := s.Register(ctx, inv, wrongEmail, meta); err != ErrInviteEmail {
		t.Fatalf("wrong email: %v", err)
	}

	n := NewUser{Username: "dave", Email: "dave@example.com", Password: "a very good password", Role: RoleAdmin}
	token, u, err := s.Register(ctx, inv, n, meta)
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != RoleUser {
		t.Errorf("role should come from the invite, got %q", u.Role)
	}
	if _, err := s.Authenticate(ctx, token); err != nil {
		t.Fatalf("session after register: %v", err)
	}

	n.Username, n.Email = "dave2", "dave2@example.com"
	if _, _, err := s.Register(ctx, inv, n, meta); err != ErrInvalidInvite {
		t.Fatalf("reused invite: %v", err)
	}
}
