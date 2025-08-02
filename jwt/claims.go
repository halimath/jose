package jwt

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// The "sub" (subject) claim identifies the principal that is the
	// subject of the JWT.  The claims in a JWT are normally statements
	// about the subject.  The subject value MUST either be scoped to be
	// locally unique in the context of the issuer or be globally unique.
	// The processing of this claim is generally application specific.  The
	// "sub" value is a case-sensitive string containing a StringOrURI
	// value.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2)
	ClaimSubject = "sub"

	// The "iss" (issuer) claim identifies the principal that issued the
	// JWT.  The processing of this claim is generally application specific.
	// The "iss" value is a case-sensitive string containing a StringOrURI
	// value.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1)
	ClaimIssuer = "iss"

	// The "aud" (audience) claim identifies the recipients that the JWT is
	// intended for.  Each principal intended to process the JWT MUST
	// identify itself with a value in the audience claim.  If the principal
	// processing the claim does not identify itself with a value in the
	// "aud" claim when this claim is present, then the JWT MUST be
	// rejected.  In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value.  In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value.  The
	// interpretation of audience values is generally application specific.
	// Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3)
	ClaimAudience = "aud"

	// The "exp" (expiration time) claim identifies the expiration time on
	// or after which the JWT MUST NOT be accepted for processing.  The
	// processing of the "exp" claim requires that the current date/time
	// MUST be before the expiration date/time listed in the "exp" claim.
	// Implementers MAY provide for some small leeway, usually no more than
	// a few minutes, to account for clock skew.  Its value MUST be a number
	// containing a NumericDate value.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4)
	ClaimExpirationTime = "exp"

	// The "nbf" (not before) claim identifies the time before which the JWT
	// MUST NOT be accepted for processing.  The processing of the "nbf"
	// claim requires that the current date/time MUST be after or equal to
	// the not-before date/time listed in the "nbf" claim.  Implementers MAY
	// provide for some small leeway, usually no more than a few minutes, to
	// account for clock skew.  Its value MUST be a number containing a
	// NumericDate value.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)
	ClaimNotBefore = "nbf"

	// The "iat" (issued at) claim identifies the time at which the JWT was
	// issued.  This claim can be used to determine the age of the JWT.  Its
	// value MUST be a number containing a NumericDate value.  Use of this
	// claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6)
	ClaimIssuedAt = "iat"

	// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	// The identifier value MUST be assigned in a manner that ensures that
	// there is a negligible probability that the same value will be
	// accidentally assigned to a different data object; if the application
	// uses multiple issuers, collisions MUST be prevented among values
	// produced by different issuers as well.  The "jti" claim can be used
	// to prevent the JWT from being replayed.  The "jti" value is a case-
	// sensitive string.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7)
	ClaimID = "jti"
)

// Claims is map of string claim names to values.
type Claims map[string]any

// UnmarshalClaims unmarshals JSON data into a Claims value.
// It is a convenience function to invoke json.Unmarshal and returning the
// claims value.
func UnmarshalClaims(data []byte) (claims Claims, err error) {
	err = json.Unmarshal(data, &claims)
	return
}

// Has returns true iff claims contains a claim named claim.
func (claims Claims) Has(claim string) bool {
	_, ok := claims[claim]
	return ok
}

// GetString returns the named claim's value from claims as a string. If claims
// contains no such claim an empty string is returned. If claims contains claim
// but it's value is not of type string, an error is returned.
func (claims Claims) GetString(claim string) (string, error) {
	v, ok := claims[claim]
	if !ok {
		return "", nil
	}

	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("claim value for %s is not of type string: %v", claim, v)
	}

	return s, nil
}

// GetInt returns the named claim's value from claims as an int64. If claims
// contains no such claim 0 is returned. If the claims contains claim but the
// value is neither an int, a float or a json.Number, an error is returned.
func (claims Claims) GetInt(claim string) (int64, error) {
	v, ok := claims[claim]
	if !ok {
		return 0, nil
	}

	switch val := v.(type) {
	case int64:
		return val, nil
	case float64:
		return int64(val), nil
	case json.Number:
		i, err := val.Int64()
		if err == nil {
			return i, nil
		}
	}

	return 0, fmt.Errorf("claim value for %s is not of type number: %v", claim, v)
}

// GetTime returns the named claim's value as a time.Time.
// If the claim is not found, it returns the zero time.
// If the claim is not a numeric value, it returns an error.
func (claims Claims) GetTime(claim string) (time.Time, error) {
	v, err := claims.GetInt(claim)
	if err != nil {
		return time.Time{}, err
	}

	if v == 0 {
		return time.Time{}, err
	}

	return time.Unix(v, 0), nil
}

// GetStringSlice returns the named claim's value from claims as a slice of strings.
// If the claim is not present, it returns nil with no error.
// If the claim is a single string, it returns a slice containing that string.
// If the claim is a slice of strings, it returns it as-is.
// If the claim is not a string or a slice of strings, an error is returned.
func (claims Claims) GetStringSlice(claim string) ([]string, error) {
	v, ok := claims[claim]
	if !ok {
		return nil, nil
	}

	switch val := v.(type) {
	case string:
		return []string{val}, nil
	case []string:
		return val, nil
	case []any:
		result := make([]string, len(val))
		for i, item := range val {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("claim value for %s contains non-string element: %v", claim, item)
			}
			result[i] = s
		}
		return result, nil
	default:
		return nil, fmt.Errorf("claim value for %s is not a string or slice of strings: %v", claim, v)
	}
}

// StandardClaims defines a struct that contains the standard JWT claims as
// defined in RFC7519 section 4.1.
// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1)
type StandardClaims struct {
	// The "sub" (subject) claim identifies the principal that is the
	// subject of the JWT.  The claims in a JWT are normally statements
	// about the subject.  The subject value MUST either be scoped to be
	// locally unique in the context of the issuer or be globally unique.
	// The processing of this claim is generally application specific.  The
	// "sub" value is a case-sensitive string containing a StringOrURI
	// value.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2)
	Subject string `json:"sub,omitempty"`

	// The "iss" (issuer) claim identifies the principal that issued the
	// JWT.  The processing of this claim is generally application specific.
	// The "iss" value is a case-sensitive string containing a StringOrURI
	// value.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1)
	Issuer string `json:"iss,omitempty"`

	// The "aud" (audience) claim identifies the recipients that the JWT is
	// intended for.  Each principal intended to process the JWT MUST
	// identify itself with a value in the audience claim.  If the principal
	// processing the claim does not identify itself with a value in the
	// "aud" claim when this claim is present, then the JWT MUST be
	// rejected.  In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value.  In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value.  The
	// interpretation of audience values is generally application specific.
	// Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3)
	Audience []string `json:"aud,omitempty"`

	// The "exp" (expiration time) claim identifies the expiration time on
	// or after which the JWT MUST NOT be accepted for processing.  The
	// processing of the "exp" claim requires that the current date/time
	// MUST be before the expiration date/time listed in the "exp" claim.
	// Implementers MAY provide for some small leeway, usually no more than
	// a few minutes, to account for clock skew.  Its value MUST be a number
	// containing a NumericDate value.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4)
	ExpirationTime int64 `json:"exp,omitempty"`

	// The "nbf" (not before) claim identifies the time before which the JWT
	// MUST NOT be accepted for processing.  The processing of the "nbf"
	// claim requires that the current date/time MUST be after or equal to
	// the not-before date/time listed in the "nbf" claim.  Implementers MAY
	// provide for some small leeway, usually no more than a few minutes, to
	// account for clock skew.  Its value MUST be a number containing a
	// NumericDate value.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)
	NotBefore int64 `json:"nbf,omitempty"`

	// The "iat" (issued at) claim identifies the time at which the JWT was
	// issued.  This claim can be used to determine the age of the JWT.  Its
	// value MUST be a number containing a NumericDate value.  Use of this
	// claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6)
	IssuedAt int64 `json:"iat,omitempty"`

	// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	// The identifier value MUST be assigned in a manner that ensures that
	// there is a negligible probability that the same value will be
	// accidentally assigned to a different data object; if the application
	// uses multiple issuers, collisions MUST be prevented among values
	// produced by different issuers as well.  The "jti" claim can be used
	// to prevent the JWT from being replayed.  The "jti" value is a case-
	// sensitive string.  Use of this claim is OPTIONAL.
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7)
	ID string `json:"jti,omitempty"`
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
