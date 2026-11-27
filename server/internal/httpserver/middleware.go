package httpserver

import (
	"errors"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/andrei-soimu/KumoKeep/server/internal/auth"
	"github.com/andrei-soimu/KumoKeep/server/internal/config"
)

// securityHeaders sets headers common to every response. The CSP is set per
// handler group: strict for the API (apiHeaders), and for the web app by the
// web package, because SvelteKit carries its script hashes in a <meta> CSP.
func securityHeaders(cfg *config.Config) func(http.Handler) http.Handler {
	hsts := cfg.SecureCookies()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func apiHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// requireUser authenticates the session cookie and puts the user in the context.
func (s *Server) requireUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.cfg.SessionCookieName())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "login required")
			return
		}
		u, err := s.auth.Authenticate(r.Context(), c.Value)
		if errors.Is(err, auth.ErrUnauthenticated) {
			s.clearSessionCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "login required")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u, c.Value)))
	})
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.Handler {
	return s.requireUser(func(w http.ResponseWriter, r *http.Request) {
		if u, _ := auth.UserFrom(r.Context()); u.Role != auth.RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "admin only")
			return
		}
		next(w, r)
	})
}

func (s *Server) clientMeta(r *http.Request) auth.ClientMeta {
	return auth.ClientMeta{IP: s.clientIP(r), UserAgent: r.UserAgent()}
}

// clientIP returns the client address. With TrustProxy it uses the rightmost
// X-Forwarded-For entry, i.e. the one appended by our own reverse proxy;
// entries further left are client-controlled and can't be trusted.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// Never log query strings: they can carry tokens (invite links, shares).
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"dur_ms", time.Since(start).Milliseconds(), "ip", s.clientIP(r))
	})
}

func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic", "err", v, "path", r.URL.Path, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
