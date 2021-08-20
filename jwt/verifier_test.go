package jwt

import (
	"testing"
	"time"

	"github.com/halimath/jose/jws"
)

func TestVerifyIssuer(t *testing.T) {
	v := Issuer("foo")

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			Issuer: "foo",
		},
	}); err != nil {
		t.Error(err)
	}

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			Issuer: "bar",
		},
	}); err == nil {
		t.Error("expected error but got nil")
	}
}

func TestVerifyAudience(t *testing.T) {
	v := Audience("foo")

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			Audience: []string{"bar", "foo"},
		},
	}); err != nil {
		t.Error(err)
	}

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			Audience: []string{"bar", "spam"},
		},
	}); err == nil {
		t.Error("expected error but got nil")
	}
}

func TestVerifyNotBefore(t *testing.T) {
	v := NotBefore(1)

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{},
	}); err == nil {
		t.Error("expected error but got nil")

	}

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			NotBefore: time.Now().Unix(),
		},
	}); err != nil {
		t.Error(err)
	}

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			NotBefore: time.Now().Add(10 * time.Second).Unix(),
		},
	}); err == nil {
		t.Error("expected error but got nil")
	}
}

func TestVerifyExpirationTime(t *testing.T) {
	v := ExpirationTime(1)

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{},
	}); err == nil {
		t.Error("expected error but got nil")
	}

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			ExpirationTime: time.Now().Unix(),
		},
	}); err == nil {
		t.Error("expected error but got nil")
	}

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			ExpirationTime: time.Now().Add(10 * time.Second).Unix(),
		},
	}); err != nil {
		t.Error(err)
	}
}

func TestVerifyMaxAge(t *testing.T) {
	v := MaxAge(1 * time.Second)

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{},
	}); err == nil {
		t.Error("expected error but got nil")
	}

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			IssuedAt: time.Now().Add(-10 * time.Second).Unix(),
		},
	}); err == nil {
		t.Error("expected error but got nil")
	}

	if err := v.Verify(&Token{
		standardClaims: StandardClaims{
			IssuedAt: time.Now().Unix(),
		},
	}); err != nil {
		t.Error(err)
	}
}

func TestVerifySignature(t *testing.T) {
	sigValid := jws.HS256([]byte("secret"))
	sigInvalid := jws.HS256([]byte("another-secret"))

	token, err := Sign(sigValid, StandardClaims{})

	if err != nil {
		t.Fatal(err)
	}

	if err := token.Verify(Signature(sigValid)); err != nil {
		t.Error(err)
	}

	if err := token.Verify(Signature(sigInvalid)); err == nil {
		t.Errorf("expected verification error but got nil")
	}
}
