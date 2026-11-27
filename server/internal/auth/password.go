package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the Argon2id cost parameters. They are encoded into every
// hash, so they can be raised later; old hashes are upgraded on next login.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultParams: 64 MiB, 3 passes, 2 lanes (RFC 9106 / OWASP range).
var DefaultParams = Argon2Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLen: 16, KeyLen: 32}

const (
	MinPasswordLen = 12
	MaxPasswordLen = 1024 // bytes; bounds hashing work for hostile input
)

var (
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d bytes", MaxPasswordLen)
	errInvalidHash      = errors.New("invalid password hash format")
)

// hashSlots caps concurrent Argon2 computations so a burst of login attempts
// can't exhaust memory (each hash uses Params.Memory).
var hashSlots = make(chan struct{}, 4)

// ValidateNewPassword checks the policy for passwords being set.
func ValidateNewPassword(pw string) error {
	if len(pw) > MaxPasswordLen {
		return ErrPasswordTooLong
	}
	if utf8.RuneCountInString(pw) < MinPasswordLen {
		return ErrPasswordTooShort
	}
	return nil
}

// HashPassword returns an encoded Argon2id hash:
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>
func HashPassword(pw string) (string, error) {
	return hashWithParams(pw, DefaultParams)
}

func hashWithParams(pw string, p Argon2Params) (string, error) {
	if len(pw) > MaxPasswordLen {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := derive(pw, salt, p)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks pw against an encoded hash in constant time.
// needsRehash is true when the hash uses weaker parameters than DefaultParams.
func VerifyPassword(pw, encoded string) (ok, needsRehash bool, err error) {
	if len(pw) > MaxPasswordLen {
		return false, false, nil
	}
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	got := derive(pw, salt, p)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	needsRehash = p.Memory < DefaultParams.Memory || p.Iterations < DefaultParams.Iterations ||
		p.Parallelism != DefaultParams.Parallelism || p.KeyLen != DefaultParams.KeyLen
	return true, needsRehash, nil
}

func derive(pw string, salt []byte, p Argon2Params) []byte {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return argon2.IDKey([]byte(pw), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, errInvalidHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, errInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, errInvalidHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return p, nil, nil, errInvalidHash
	}
	// Refuse absurd parameters from a tampered database row.
	if p.Memory == 0 || p.Memory > 1024*1024 || p.Iterations == 0 || p.Iterations > 20 || p.Parallelism == 0 {
		return p, nil, nil, errInvalidHash
	}
	p.SaltLen, p.KeyLen = uint32(len(salt)), uint32(len(key))
	return p, salt, key, nil
}
