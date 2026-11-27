package auth

import (
	"context"

	"github.com/andrei-soimu/KumoKeep/server/internal/db/store"
)

type userKey struct{}
type tokenKey struct{}

// WithUser returns a context carrying the authenticated user and their session token.
func WithUser(ctx context.Context, u store.User, token string) context.Context {
	ctx = context.WithValue(ctx, userKey{}, u)
	return context.WithValue(ctx, tokenKey{}, token)
}

// UserFrom returns the authenticated user, if any.
func UserFrom(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(userKey{}).(store.User)
	return u, ok
}

// TokenFrom returns the session token of the authenticated request, if any.
func TokenFrom(ctx context.Context) string {
	t, _ := ctx.Value(tokenKey{}).(string)
	return t
}
