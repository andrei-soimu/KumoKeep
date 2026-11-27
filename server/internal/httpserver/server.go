// Package httpserver wires KumoKeep's HTTP routes and middleware.
package httpserver

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/andrei-soimu/KumoKeep/server/internal/auth"
	"github.com/andrei-soimu/KumoKeep/server/internal/config"
	"github.com/andrei-soimu/KumoKeep/server/internal/web"
)

type Server struct {
	cfg  *config.Config
	auth *auth.Service
	log  *slog.Logger

	loginByIP      *rateLimiter
	loginByAccount *rateLimiter
}

func New(cfg *config.Config, authSvc *auth.Service, log *slog.Logger) *Server {
	return &Server{
		cfg:            cfg,
		auth:           authSvc,
		log:            log,
		loginByIP:      newRateLimiter(20, 15*time.Minute),
		loginByAccount: newRateLimiter(5, 15*time.Minute),
	}
}

// Handler returns the root handler with all routes and middleware.
func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/health", s.handleHealth)
	api.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	api.HandleFunc("POST /api/v1/auth/register", s.handleRegister)
	api.Handle("POST /api/v1/auth/logout", s.requireUser(s.handleLogout))
	api.Handle("GET /api/v1/me", s.requireUser(s.handleMe))
	api.Handle("POST /api/v1/admin/invites", s.requireAdmin(s.handleCreateInvite))
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})

	root := http.NewServeMux()
	root.Handle("/api/", apiHeaders(api))
	root.Handle("/", web.Handler())

	// Rejects cross-origin state-changing browser requests (CSRF) using
	// Sec-Fetch-Site / Origin. Non-browser clients send neither and pass.
	csrf := http.NewCrossOriginProtection()

	var h http.Handler = root
	h = csrf.Handler(h)
	h = securityHeaders(s.cfg)(h)
	h = s.logRequests(h)
	h = s.recoverPanics(h)
	return h
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
