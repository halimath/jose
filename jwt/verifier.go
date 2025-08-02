package jwt

import (
	"fmt"
	"time"

	"github.com/halimath/jose/jws"
)

// Verifier defines the interface for types that verify validity of a
// given token.
type Verifier interface {
	Verify(token *Token) error
}

// VerifierFunc is a convenience type that wraps a single function as a Verifier.
type VerifierFunc func(token *Token) error

func (f VerifierFunc) Verify(token *Token) error {
	return f(token)
}

// --

// Signature returns a verifier that verifies the token's signature using the given signature method.
func Signature(signatureVerifier jws.Verifier) Verifier {
	return VerifierFunc(func(token *Token) error {
		err := token.VerifySignature(signatureVerifier)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrVerificationFailed, err)
		}
		return nil
	})
}

// Issuer returns a verifier that verifies the issuer for a given value.
func Issuer(issuer string) Verifier {
	return VerifierFunc(func(token *Token) error {
		iss, err := token.claims.GetString(ClaimIssuer)
		if err != nil {
			return fmt.Errorf("invalid issuer: %v", err)
		}
		if iss != issuer {
			return fmt.Errorf("invalid issuer: %s", iss)
		}
		return nil
	})
}

// Audience returns a verifier that verifies whether the audience claim contains a given value.
func Audience(audience string) Verifier {
	return VerifierFunc(func(token *Token) error {
		aud, err := token.claims.GetStringSlice(ClaimAudience)
		if err != nil {
			return fmt.Errorf("error verifying aud: %v", err)
		}

		if len(aud) == 0 {
			return fmt.Errorf("token is missing aud claim")
		}

		for _, aud := range aud {
			if aud == audience {
				return nil
			}
		}

		return fmt.Errorf("missing required audience: %s", audience)
	})
}

// NotBefore returns a verifier that verifies that a token is not used before the given not before time.
// The function accepts a leeway to compensate for differences in server time.
// If the token does not carry a not before claim, this verifier rejects the token.
func NotBefore(leeway time.Duration) Verifier {
	return VerifierFunc(func(token *Token) error {
		notBefore, err := token.claims.GetTime(ClaimNotBefore)
		if err != nil {
			return fmt.Errorf("error verifying nbf: %v", err)
		}

		if notBefore.IsZero() {
			return fmt.Errorf("token is missing nbf")
		}

		delta := time.Until(notBefore)
		if delta > leeway {
			return fmt.Errorf("token used before nbf: %s", notBefore.Format(time.RFC3339))
		}

		return nil
	})
}

// ExpirationTime returns a verifier that verifies that a token is not expired.
// The function accepts a leeway to compensate for differences in server time.
// If the token does not carry a expiration time claim, this verifier rejects the token.
func ExpirationTime(leeway time.Duration) Verifier {
	return VerifierFunc(func(token *Token) error {
		exp, err := token.claims.GetTime(ClaimExpirationTime)
		if err != nil {
			return fmt.Errorf("verification of exp failed: %v", err)
		}

		if exp.IsZero() {
			return fmt.Errorf("token is missing exp")
		}

		if time.Since(exp) > leeway {
			return fmt.Errorf("token used after exp: %s", exp.Format(time.RFC3339))
		}

		return nil
	})
}

// MaxAge returns a verifier that verifies that a token is not older than the given duration.
// The verifier uses the issued at claim. If the token does not carry an issued at claim, this verifier
// rejects the token.
func MaxAge(maxAge time.Duration) Verifier {
	return VerifierFunc(func(token *Token) error {
		iat, err := token.claims.GetTime(ClaimIssuedAt)
		if err != nil {
			return fmt.Errorf("verification of iat failed: %v", err)
		}

		if iat.IsZero() {
			return fmt.Errorf("token is missing iat")
		}

		if iat.Before(time.Now().Add(-maxAge)) {
			return fmt.Errorf("token too old: %s", iat.Format(time.RFC3339))
		}

		return nil
	})
}
