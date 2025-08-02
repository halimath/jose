package jwt

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/halimath/jose/jws"
)

const (
	// the value of a token's header "typ" parameter to define this token as a JWT,
	// see RFC7519, section 5.1 for details
	// (https://datatracker.ietf.org/doc/html/rfc7519#section-5.1)
	HeaderType = "JWT"
)

var (
	// Sentinel error value returned (maybe wrapped) to indicate that a passed
	// token is not a structural valid JWT.
	ErrInvalidToken = errors.New("invalid token")

	// Sentinel error value returned (maybe wrapped) from verification calls to
	// indicate that a given (structual valid) JWT is not valid according to
	// the performed verification steps.
	ErrVerificationFailed = errors.New("verification failed")
)

// Token implements an assembled JWT. It's a wrapper around a jws.JWS
// with methods to access the JSON payload in a convenient manner.
type Token struct {
	// the underlying JWS container holding the data
	jws.JWS

	// The claims contained in this Token in structured form
	claims Claims
}

// StandardClaims returns t's RFC defined claims.
func (t *Token) StandardClaims() (claims StandardClaims) {
	_ = json.Unmarshal(patchAudClaim(t.Payload()), &claims)
	// We do not handle any error here as both Decode and Sign assure that payload
	// contains valid data
	return
}

// Claims unmarshals the claims JSON data contained in t into the claims value given which must
// be a pointer to some datastructure that json.Unmarshal can handle.
// The method returns the error returned from json.Unmarshal
func (t *Token) UnmarshalClaims(claims interface{}) error {
	return json.Unmarshal(patchAudClaim(t.Payload()), claims)
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

// Sign creates a signed JWT and returns it in compact serialization. It uses
// claims to produce the token's payload by applying json.Marshal to it. It uses
// signer to create the signature. It returns a non-nil error in case either
// marshaling the claims or signing the token fails. In such case, the returned
// token is invalid.
func Sign(signer jws.Signer, claims any) (*Token, error) {
	serializedClaims, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	return SignSerialized(signer, serializedClaims)
}

// SignSerialized creates a signed JWT and returns it in compact serialization.
// It uses payload as the serialized payload data to embed in the token.
// The payload is not checked to be a valid JSON string, thus, passing in
// invalid payload causes SignSerialized to produce an invalid JWT.
func SignSerialized(signer jws.Signer, payload []byte) (*Token, error) {
	claims, err := UnmarshalClaims(patchAudClaim(payload))
	if err != nil {
		return nil, fmt.Errorf("Invalid JWT payload: %v", err)
	}

	j, err := jws.Sign(signer, payload, jws.Header{
		Type: HeaderType,
	})
	if err != nil {
		return nil, err
	}

	return &Token{
		JWS:    *j,
		claims: claims,
	}, nil
}

// Decode decodes the given compact token string, parses header and claims for valid
// JSON objects and returns a token instance containing the parsed values.
func Decode(compact string) (*Token, error) {
	sig, err := jws.ParseCompact(compact)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if sig.Header().Type != HeaderType {
		return nil, fmt.Errorf("%w: token is not of type %s: found %q", ErrInvalidToken, HeaderType, sig.Header().Type)
	}

	tok := Token{
		JWS: *sig,
	}

	if err := json.Unmarshal(patchAudClaim(sig.Payload()), &tok.claims); err != nil {
		return nil, fmt.Errorf("%w: payload is not a valid JSON object: %v", ErrInvalidToken, err)
	}

	return &tok, nil
}

// patchAudClaim patches an "aud" claim found in in to be a list of strings.
// According to https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// "aud" may be either a list of strings or a single string. To enable
// json.Unmarshal we need a slice of strings. Thus, this function checks for
// an "aud" claim and if the value is a bare string it is wrapped in a list.
// All other values are ignored.
// This function causes a double JSON parsing (one run to patch the claim)
// and another call to actually unmarshal into the StandardClaims struct.
// This is a known issue.
func patchAudClaim(in []byte) []byte {
	var claims map[string]any
	if err := json.Unmarshal(in, &claims); err != nil {
		// Just return the original payload; the parsing error will pop-up
		// again
		return in
	}
	aud, ok := claims["aud"]
	if !ok {
		return in
	}
	if s, ok := aud.(string); ok {
		claims["aud"] = []string{s}
	}

	data, err := json.Marshal(claims)
	if err != nil {
		// This can never happen
		panic(fmt.Sprintf("weird error during 'aud' claim patching: %v", err))
	}

	return data
}
