package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected hash format: %s", h)
	}

	ok, rehash, err := VerifyPassword("correct horse battery staple", h)
	if err != nil || !ok || rehash {
		t.Fatalf("verify correct: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	ok, _, err = VerifyPassword("wrong password!!", h)
	if err != nil || ok {
		t.Fatalf("verify wrong: ok=%v err=%v", ok, err)
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same password here")
	b, _ := HashPassword("same password here")
	if a == b {
		t.Fatal("two hashes of the same password are equal")
	}
}

func TestNeedsRehashForWeakParams(t *testing.T) {
	weak := Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}
	h, err := hashWithParams("some long password", weak)
	if err != nil {
		t.Fatal(err)
	}
	ok, rehash, err := VerifyPassword("some long password", h)
	if err != nil || !ok || !rehash {
		t.Fatalf("ok=%v rehash=%v err=%v", ok, rehash, err)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	for _, h := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$a2V5",
		"$argon2id$v=18$m=65536,t=3,p=2$c2FsdA$a2V5",
		"$argon2id$v=19$m=99999999,t=3,p=2$c2FsdA$a2V5",
		"$argon2id$v=19$m=65536,t=3,p=2$!!!$a2V5",
	} {
		if ok, _, err := VerifyPassword("password", h); ok || err == nil {
			t.Errorf("hash %q: ok=%v err=%v, want error", h, ok, err)
		}
	}
}

func TestValidateNewPassword(t *testing.T) {
	if err := ValidateNewPassword("short"); err != ErrPasswordTooShort {
		t.Errorf("short: %v", err)
	}
	if err := ValidateNewPassword(strings.Repeat("a", MaxPasswordLen+1)); err != ErrPasswordTooLong {
		t.Errorf("long: %v", err)
	}
	if err := ValidateNewPassword("twelve chars"); err != nil {
		t.Errorf("ok: %v", err)
	}
}
