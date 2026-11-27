package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// NewToken returns a random 256-bit token (URL-safe base64) and its SHA-256
// hash. Only the hash is stored, so a database leak yields no usable tokens.
func NewToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken returns the SHA-256 of a token. A fast hash is fine here because
// tokens have 256 bits of entropy, unlike passwords.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
