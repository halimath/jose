package jwt

import (
	"testing"
	"time"

	"github.com/halimath/jose/jws"
)

func TestVerifyIssuer(t *testing.T) {
	v := Issuer("foo")

	t.Run("verified", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimIssuer: "foo",
			},
		}); err != nil {
			t.Error(err)
		}
	})

	t.Run("unexpected issuer", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimIssuer: "bar",
			},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("invalid issuer", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimIssuer: 17,
			},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("no issuer claim", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})
}

func TestVerifyAudience(t *testing.T) {
	v := Audience("foo")

	t.Run("verified", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimAudience: []string{"bar", "foo"},
			},
		}); err != nil {
			t.Error(err)
		}
	})

	t.Run("missing aud", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimAudience: []string{"bar", "spam"},
			},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("no aud claim", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("invalid aud claim", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimAudience: 17,
			},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})
}

func TestVerifyNotBefore(t *testing.T) {
	v := NotBefore(1)

	t.Run("missing notBefore", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("valid notBefore", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimNotBefore: time.Now().Unix(),
			},
		}); err != nil {
			t.Error(err)
		}
	})

	t.Run("future notBefore", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimNotBefore: time.Now().Add(10 * time.Second).Unix(),
			},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})
}

func TestVerifyExpirationTime(t *testing.T) {
	v := ExpirationTime(1)

	t.Run("missing expiration", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("expired", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimExpirationTime: time.Now().Unix(),
			},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("valid expiration", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimExpirationTime: time.Now().Add(10 * time.Second).Unix(),
			},
		}); err != nil {
			t.Error(err)
		}
	})
}

func TestVerifyMaxAge(t *testing.T) {
	v := MaxAge(1 * time.Second)

	t.Run("missing issuedAt", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("too old", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimIssuedAt: time.Now().Add(-10 * time.Second).Unix(),
			},
		}); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("recent enough", func(t *testing.T) {
		if err := v.Verify(&Token{
			claims: Claims{
				ClaimIssuedAt: time.Now().Unix(),
			},
		}); err != nil {
			t.Error(err)
		}
	})
}

func TestVerifySignature(t *testing.T) {
	sigValid := jws.HS256([]byte("secret"))
	sigInvalid := jws.HS256([]byte("another-secret"))

	token, err := Sign(sigValid, StandardClaims{})

	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid signature", func(t *testing.T) {
		if err := token.Verify(Signature(sigValid)); err != nil {
			t.Error(err)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		if err := token.Verify(Signature(sigInvalid)); err == nil {
			t.Errorf("expected verification error but got nil")
		}
	})
}
