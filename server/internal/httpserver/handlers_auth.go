package httpserver

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andrei-soimu/KumoKeep/server/internal/auth"
	"github.com/andrei-soimu/KumoKeep/server/internal/db/store"
)

type userDTO struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func toUserDTO(u store.User) userDTO {
	return userDTO{ID: u.ID, Username: u.Username, Email: u.Email, Role: u.Role, CreatedAt: time.Unix(u.CreatedAt, 0).UTC()}
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionCookieName(),
		Value:    token,
		Path:     "/",
		MaxAge:   int(auth.SessionTTL / time.Second),
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	meta := s.clientMeta(r)
	account := strings.ToLower(strings.TrimSpace(req.Login))

	// Per-IP limit counts every attempt; per-account limit counts failures only,
	// so an attacker can't lock out a user from a single IP indefinitely.
	if !s.loginByIP.Allow(meta.IP) || s.loginByAccount.Blocked(account) {
		s.auth.Audit(r.Context(), "", "login.rate_limited", meta, map[string]any{"login": account})
		w.Header().Set("Retry-After", "900")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts, try again later")
		return
	}

	token, u, err := s.auth.Login(r.Context(), req.Login, req.Password, meta)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		s.loginByAccount.Allow(account)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.loginByAccount.Reset(account)
	s.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, toUserDTO(u))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Logout(r.Context(), auth.TokenFrom(r.Context())); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	writeJSON(w, http.StatusOK, toUserDTO(u))
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email        string `json:"email"`
		Role         string `json:"role"`
		ExpiresHours int    `json:"expires_hours"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Role == "" {
		req.Role = auth.RoleUser
	}
	admin, _ := auth.UserFrom(r.Context())
	ttl := time.Duration(req.ExpiresHours) * time.Hour
	token, expires, err := s.auth.CreateInvite(r.Context(), admin, req.Email, req.Role, ttl, s.clientMeta(r))
	if errors.Is(err, auth.ErrInvalidRole) || errors.Is(err, auth.ErrInvalidEmail) {
		writeError(w, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	link := s.cfg.BaseURL.JoinPath("register")
	link.RawQuery = url.Values{"invite": {token}}.Encode()
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      token,
		"url":        link.String(),
		"expires_at": expires.UTC(),
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Invite   string `json:"invite"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	meta := s.clientMeta(r)
	if !s.loginByIP.Allow(meta.IP) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")
		return
	}
	token, u, err := s.auth.Register(r.Context(), req.Invite, auth.NewUser{
		Username: req.Username, Email: req.Email, Password: req.Password,
	}, meta)
	switch {
	case errors.Is(err, auth.ErrInvalidInvite):
		writeError(w, http.StatusForbidden, "invalid_invite", err.Error())
		return
	case errors.Is(err, auth.ErrUserExists):
		writeError(w, http.StatusConflict, "user_exists", err.Error())
		return
	case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrInvalidEmail),
		errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong),
		errors.Is(err, auth.ErrInviteEmail):
		writeError(w, http.StatusBadRequest, "invalid_input", err.Error())
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	s.setSessionCookie(w, token)
	writeJSON(w, http.StatusCreated, toUserDTO(u))
}
