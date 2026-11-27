// Command kumokeep runs the KumoKeep server and admin tasks.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/andrei-soimu/KumoKeep/server/internal/auth"
	"github.com/andrei-soimu/KumoKeep/server/internal/config"
	"github.com/andrei-soimu/KumoKeep/server/internal/db"
	"github.com/andrei-soimu/KumoKeep/server/internal/httpserver"
)

var version = "dev"

const usage = `Usage: kumokeep <command> [flags]

Commands:
  serve                    Run the server (default)
  admin create [flags]     Create a user (prompts for the password)
  version                  Print the version

Configuration is read from KUMOKEEP_* environment variables; see docs/ARCHITECTURE.md.
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "admin":
		err = admin(args)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// setup loads config, builds the logger, opens the database and runs migrations.
func setup(ctx context.Context, newLog func(*config.Config) *slog.Logger) (*config.Config, *slog.Logger, *auth.Service, func(), error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log := newLog(cfg)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create data dir: %w", err)
	}
	database, err := db.Open(ctx, cfg.DBPath())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := db.Migrate(ctx, database); err != nil {
		database.Close()
		return nil, nil, nil, nil, err
	}
	return cfg, log, auth.NewService(database, log), func() { database.Close() }, nil
}

func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, log, authSvc, closeDB, err := setup(ctx, func(cfg *config.Config) *slog.Logger {
		if cfg.Dev {
			return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		}
		return slog.New(slog.NewJSONHandler(os.Stdout, nil))
	})
	if err != nil {
		return err
	}
	defer closeDB()

	go cleanupLoop(ctx, authSvc, log)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           httpserver.New(cfg, authSvc, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("kumokeep listening", "addr", cfg.Addr, "base_url", cfg.BaseURL.String(), "version", version)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func cleanupLoop(ctx context.Context, authSvc *auth.Service, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := authSvc.CleanupExpiredSessions(ctx); err != nil && ctx.Err() == nil {
			log.Error("session cleanup failed", "err", err)
		} else if n > 0 {
			log.Info("removed expired sessions", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func admin(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: kumokeep admin create --username NAME --email EMAIL [--role admin|user]")
	}
	fs := flag.NewFlagSet("admin create", flag.ExitOnError)
	username := fs.String("username", "", "username (required)")
	email := fs.String("email", "", "email address (required)")
	role := fs.String("role", auth.RoleAdmin, "role: admin or user")
	_ = fs.Parse(args[1:])
	if *username == "" || *email == "" {
		fs.Usage()
		os.Exit(2)
	}

	password, err := readPassword()
	if err != nil {
		return err
	}

	ctx := context.Background()
	_, _, authSvc, closeDB, err := setup(ctx, func(*config.Config) *slog.Logger {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	})
	if err != nil {
		return err
	}
	defer closeDB()

	u, err := authSvc.CreateUser(ctx, auth.NewUser{Username: *username, Email: *email, Password: password, Role: *role})
	if err != nil {
		return err
	}
	authSvc.Audit(ctx, u.ID, "user.created_cli", auth.ClientMeta{IP: "cli"}, map[string]any{"role": u.Role})
	fmt.Printf("created %s %q (%s)\n", u.Role, u.Username, u.ID)
	return nil
}

// readPassword prompts twice on a terminal, or reads one line from a pipe.
// Passwords are never taken from flags or env vars, which leak via ps and logs.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repeat password: ")
	p2, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", errors.New("passwords do not match")
	}
	return string(p1), nil
}
