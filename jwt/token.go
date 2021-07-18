package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/halimath/jwx/jws"
)

var (
	ErrInvalidToken = errors.New("invalid token")

	ErrVerificationFailed = errors.New("verification failed")
)

// StandardClaims defines a struct that contains the standard JWT claims as defined in RFC7519 section 4.1
// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1)
type StandardClaims struct {
	ID             string   `json:"jti,omitempty"`
	Subject        string   `json:"sub,omitempty"`
	Issuer         string   `json:"iss,omitempty"`
	Audience       []string `json:"aud,omitempty"`
	ExpirationTime int64    `json:"exp,omitempty"`
	NotBefore      int64    `json:"nbf,omitempty"`
	IssuedAt       int64    `json:"iat,omitempty"`
}

// GetExpirationTime returns the contained expiration time as a time.Time value.
func (s *StandardClaims) GetExpirationTime() time.Time {
	return time.Unix(s.ExpirationTime, 0)
}

// SetExpirationTime populates the expiration time from the given time.Time value.
func (s *StandardClaims) SetExpirationTime(exp time.Time) *StandardClaims {
	s.ExpirationTime = exp.Unix()
	return s
}

// GetNotBefore returns the contained not before time as a time.Time value.
func (s *StandardClaims) GetNotBefore() time.Time {
	return time.Unix(s.NotBefore, 0)
}

// SetNotBefore populates the not before time from the given time.Time value.
func (s *StandardClaims) SetNotBefore(nbf time.Time) *StandardClaims {
	s.NotBefore = nbf.Unix()
	return s
}

// GetIssuedAt returns the contained issued at time as a time.Time value.
func (s *StandardClaims) GetIssuedAt() time.Time {
	return time.Unix(s.IssuedAt, 0)
}

// SetIssuedAt populates the issued at time from the given time.Time value.
func (s *StandardClaims) SetIssuedAt(iat time.Time) *StandardClaims {
	s.IssuedAt = iat.Unix()
	return s
}

// --

// Token implements an assembled JWT. It's a wrapper around a jws.JWS
// with methods to access the JSON payload in a convenient manner.
type Token struct {
	jws.JWS
	standardClaims StandardClaims
}

// Claims returns a copy of the token's standard claims.
func (t *Token) StandardClaims() StandardClaims {
	return t.standardClaims
}

// Claims unmarshals the claims JSON data contained in t into the claims value given which must
// be a pointer to some datastructure that json.Unmarshal can handle.
// The method returns the error returned from json.Unmarshal
func (t *Token) Claims(claims interface{}) error {
	return json.Unmarshal(t.Payload(), claims)
}

// Verify verifies the token to using the given verifier. It returns the
// first non-nil error received from a verify or nil if no verifier rejects
// the token.
func (t *Token) Verify(verifier ...Verifier) error {
	for _, v := range verifier {
		if err := v.Verify(t); err != nil {
			return fmt.Errorf("%w: %s", ErrVerificationFailed, err)
		}
	}

	return nil
}

// Sign writes the given claims into a valid JWT signed with the
// signature method associated with w.
func Sign(signer jws.Signer, claims interface{}) (*Token, error) {
	serializedClaims, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	var standardClaims StandardClaims
	switch c := claims.(type) {
	case StandardClaims:
		standardClaims = c
	default:
		err := json.Unmarshal(serializedClaims, &standardClaims)
		if err != nil {
			return nil, err
		}
	}

	j, err := jws.Sign(signer, serializedClaims, jws.Header{
		Type: "JWT",
	})
	if err != nil {
		return nil, err
	}

	return &Token{
		JWS:            *j,
		standardClaims: standardClaims,
	}, nil
}

// Decode decodes the given compact token string, parses header and claims for valid
// JSON objects and returns a token instance containing the parsed values.
func Decode(compact string) (*Token, error) {
	sig, err := jws.ParseCompact(compact)
	if err != nil {
		return nil, err
	}

	var standardClaims StandardClaims
	if err := json.Unmarshal(sig.Payload(), &standardClaims); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidToken, err)
	}

	return &Token{
		JWS:            *sig,
		standardClaims: standardClaims,
	}, nil
}
