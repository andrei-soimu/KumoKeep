// Package config loads KumoKeep's configuration from environment variables.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	// Addr is the listen address. Keep it on localhost behind a reverse proxy.
	Addr string
	// DataDir holds the database, user files and caches.
	DataDir string
	// BaseURL is the public URL clients use to reach KumoKeep.
	BaseURL *url.URL
	// ContentURL is an optional separate origin for serving user content.
	ContentURL *url.URL
	// TrustProxy makes the server take the client IP from X-Forwarded-For.
	// Enable only when a reverse proxy you control sits in front.
	TrustProxy bool
	// Dev enables development conveniences (verbose logs).
	Dev bool
}

func FromEnv() (*Config, error) {
	c := &Config{
		Addr:    env("KUMOKEEP_ADDR", "127.0.0.1:8080"),
		DataDir: env("KUMOKEEP_DATA_DIR", "./data"),
	}

	var err error
	if c.BaseURL, err = parseOrigin("KUMOKEEP_BASE_URL", env("KUMOKEEP_BASE_URL", "http://localhost:8080")); err != nil {
		return nil, err
	}
	if v := os.Getenv("KUMOKEEP_CONTENT_URL"); v != "" {
		if c.ContentURL, err = parseOrigin("KUMOKEEP_CONTENT_URL", v); err != nil {
			return nil, err
		}
		if c.ContentURL.Host == c.BaseURL.Host {
			return nil, fmt.Errorf("KUMOKEEP_CONTENT_URL must be a different origin from KUMOKEEP_BASE_URL")
		}
	}
	if c.TrustProxy, err = envBool("KUMOKEEP_TRUST_PROXY"); err != nil {
		return nil, err
	}
	if c.Dev, err = envBool("KUMOKEEP_DEV"); err != nil {
		return nil, err
	}

	if c.DataDir, err = filepath.Abs(c.DataDir); err != nil {
		return nil, fmt.Errorf("KUMOKEEP_DATA_DIR: %w", err)
	}
	return c, nil
}

func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "kumokeep.db") }

// SecureCookies reports whether cookies get the Secure flag (HTTPS deployments).
func (c *Config) SecureCookies() bool { return c.BaseURL.Scheme == "https" }

// SessionCookieName uses the __Host- prefix over HTTPS, which browsers only
// accept for Secure, host-only cookies with Path=/.
func (c *Config) SessionCookieName() string {
	if c.SecureCookies() {
		return "__Host-kk_session"
	}
	return "kk_session"
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

func parseOrigin(key, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%s: scheme must be http or https", key)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s: missing host", key)
	}
	return u, nil
}
