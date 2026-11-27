package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrei-soimu/KumoKeep/server/internal/auth"
	"github.com/andrei-soimu/KumoKeep/server/internal/config"
	"github.com/andrei-soimu/KumoKeep/server/internal/db"
)

type testEnv struct {
	srv    *httptest.Server
	client *http.Client
	auth   *auth.Service
}

func newTestEnv(t *testing.T) *testEnv {
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	authSvc := auth.NewService(database, log)

	cfg := &config.Config{}
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)
	cfg.BaseURL, _ = url.Parse(srv.URL)
	srv.Config.Handler = New(cfg, authSvc, log).Handler()

	jar, _ := cookiejar.New(nil)
	return &testEnv{srv: srv, client: &http.Client{Jar: jar}, auth: authSvc}
}

func (e *testEnv) do(t *testing.T, method, path, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestHealthAndHeaders(t *testing.T) {
	e := newTestEnv(t)
	resp := e.do(t, "GET", "/api/v1/health", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for k, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestLoginMeLogout(t *testing.T) {
	e := newTestEnv(t)
	_, err := e.auth.CreateUser(context.Background(), auth.NewUser{
		Username: "alice", Email: "alice@example.com", Password: "a very good password", Role: auth.RoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp := e.do(t, "GET", "/api/v1/me", "", nil); resp.StatusCode != 401 {
		t.Fatalf("me before login: %d", resp.StatusCode)
	}
	if resp := e.do(t, "POST", "/api/v1/auth/login", `{"login":"alice","password":"nope nope nope"}`, nil); resp.StatusCode != 401 {
		t.Fatalf("bad login: %d", resp.StatusCode)
	}
	resp := e.do(t, "POST", "/api/v1/auth/login", `{"login":"alice","password":"a very good password"}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	if c := resp.Cookies(); len(c) != 1 || !c[0].HttpOnly {
		t.Fatalf("session cookie missing or not HttpOnly: %+v", c)
	}

	resp = e.do(t, "GET", "/api/v1/me", "", nil)
	var me userDTO
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil || me.Username != "alice" {
		t.Fatalf("me: %d %+v %v", resp.StatusCode, me, err)
	}

	if resp := e.do(t, "POST", "/api/v1/auth/logout", "", nil); resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if resp := e.do(t, "GET", "/api/v1/me", "", nil); resp.StatusCode != 401 {
		t.Fatalf("me after logout: %d", resp.StatusCode)
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	e := newTestEnv(t)
	resp := e.do(t, "POST", "/api/v1/auth/login", `{"login":"a","password":"b"}`,
		map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST: %d, want 403", resp.StatusCode)
	}
}

func TestLoginRequiresJSON(t *testing.T) {
	e := newTestEnv(t)
	resp := e.do(t, "POST", "/api/v1/auth/login", "", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("form post: %d", resp.StatusCode)
	}
}

func TestLoginRateLimitPerAccount(t *testing.T) {
	e := newTestEnv(t)
	body := `{"login":"victim","password":"wrong password!"}`
	for i := 0; i < 5; i++ {
		if resp := e.do(t, "POST", "/api/v1/auth/login", body, nil); resp.StatusCode != 401 {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	if resp := e.do(t, "POST", "/api/v1/auth/login", body, nil); resp.StatusCode != 429 {
		t.Fatalf("6th attempt: %d, want 429", resp.StatusCode)
	}
}

func TestAdminOnlyInvites(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	for _, u := range []auth.NewUser{
		{Username: "admin", Email: "admin@example.com", Password: "a very good password", Role: auth.RoleAdmin},
		{Username: "user", Email: "user@example.com", Password: "a very good password", Role: auth.RoleUser},
	} {
		if _, err := e.auth.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}

	e.do(t, "POST", "/api/v1/auth/login", `{"login":"user","password":"a very good password"}`, nil)
	if resp := e.do(t, "POST", "/api/v1/admin/invites", `{}`, nil); resp.StatusCode != 403 {
		t.Fatalf("user creating invite: %d", resp.StatusCode)
	}

	e.do(t, "POST", "/api/v1/auth/login", `{"login":"admin","password":"a very good password"}`, nil)
	resp := e.do(t, "POST", "/api/v1/admin/invites", `{"email":"new@example.com"}`, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("admin creating invite: %d", resp.StatusCode)
	}
	var inv struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&inv)

	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Jar: jar}
	resp = e.do(t, "POST", "/api/v1/auth/register",
		`{"invite":"`+inv.Token+`","username":"newbie","email":"new@example.com","password":"a very good password"}`, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	if resp := e.do(t, "GET", "/api/v1/me", "", nil); resp.StatusCode != 200 {
		t.Fatalf("me after register: %d", resp.StatusCode)
	}
}
