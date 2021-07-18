// Package jwk provides types and functions implement JSON Web Keys as
// specified in RFC 7517 (https://datatracker.ietf.org/doc/html/rfc7517).
package jwk

import (
	"encoding/json"
)

// KeyType defines the types of keys as specified in RFC 7518 section 6.1
// (https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1)
type KeyType string

const (
	// Parameter "kty" for encoding the key type
	ParamKeyType = "kty"

	// Key Type Ellictic Curve (DSS)
	KeyTypeEC KeyType = "EC"

	// Key Type RSA
	KeyTypeRSA KeyType = "RSA"

	// Key Type Octet Stream
	KeyTypeOct KeyType = "oct"
)

// --

// KeyUse defines the types of key use as specified in RFC 7517 section 4.2
// (https://datatracker.ietf.org/doc/html/rfc7517#section-4.2)
type KeyUse string

const (
	// Parameter "use" for encoding the key use
	ParamUse = "use"

	// Public Key use for signatures
	UseSignature KeyUse = "sig"

	// Public Key use for encryption
	UseEncryption KeyUse = "enc"
)

// --

// KeyOps defines the types of key operations as specified in RFC 7517 section 4.3
// (https://datatracker.ietf.org/doc/html/rfc7517#section-4.3)
type KeyOps string

const (
	// Parameter "key_ops" for encoding the key operations
	ParamKeyOps = "key_ops"

	// compute digital signature or MAC
	KeyOpsSign KeyOps = "sign"

	// verify digital signature or MAC
	KeyOpsVerify KeyOps = "verify"

	// encrypt content
	KeyOpsEncrypt KeyOps = "encrypt"

	// decrypt content and validate decryption, if applicable
	KeyOpsDecrypt KeyOps = "decrypt"

	// encrypt key
	KeyOpsKeyWrap KeyOps = "wrapKey"

	// decrypt key and validate decryption, if applicable
	KeyOpsUnwrapKey KeyOps = "unwrapKey"

	// derive key
	KeyOpsDeriveKey KeyOps = "deriveKey"

	// derive bits not to be used as a key
	KeyOpsDeriveBits KeyOps = "deriveBits"
)

const (
	// Parameter "alg" for encoding the key's algorithm
	ParamAlg = "alg"

	// Parameter "kid" for encoding the key's ID
	ParamKID = "kid"
)

// --

// Key defines the interface implemented by all keys.
// It defines getter for the common metadata parameters
// as specified in RFC 7517 section 4
// (https://datatracker.ietf.org/doc/html/rfc7517#section-4)
type Key interface {
	// The "kty" parameter
	Type() KeyType

	// The "use" parameter
	Use() KeyUse

	// The "key_ops" parameter
	Operations() []KeyOps

	// The "alg" parameter
	Algorithm() string

	// The "kid" parameter
	ID() string

	// Marshals the key' data to the given JSON data map.
	marshalJSON(data map[string]interface{}) error

	// Unmarshals the key from the given JSON data map.
	// unmarshalJSON(data map[string]interface{}) error
}

// KeyDescription provides a simple struct that implements
// the generic getters defined by Key. It is included in
// each key's struct definition and allows the values to
// be set.
type KeyDescription struct {
	KeyUse        KeyUse
	KeyOperations []KeyOps
	KeyAlgorithm  string
	KeyID         string
}

func (k KeyDescription) Use() KeyUse {
	return k.KeyUse
}

func (k KeyDescription) Operations() []KeyOps {
	return k.KeyOperations
}

func (k KeyDescription) Algorithm() string {
	return k.KeyAlgorithm
}

func (k KeyDescription) ID() string {
	return k.KeyID
}

func (k KeyDescription) marshalJSON(data map[string]interface{}) {
	use := k.Use()
	if use != "" {
		data[ParamUse] = use
	}

	ops := k.Operations()
	if len(ops) > 0 {
		data[ParamKeyOps] = ops
	}

	alg := k.Algorithm()
	if alg != "" {
		alg := k.Algorithm()
		data[ParamAlg] = alg
	}

	kid := k.ID()
	if kid != "" {
		data[ParamKID] = kid
	}
}

// --

// KeyFilter defines a function type to use to filter Keys in a Set.
type KeyFilter func(k Key) bool

// WithID create a KeyFilter that filters Keys by ID.
func WithID(kid string) KeyFilter {
	return func(k Key) bool {
		return k.ID() == kid
	}
}

// Set implements a set of keys.
type Set []Key

// Has checks whether s contains at least one Key matching f.
func (s Set) Has(f KeyFilter) bool {
	for _, k := range s {
		if f(k) {
			return true
		}
	}
	return false
}

// First returns the first key in s which matches f or
// nil, if no key matches f.
func (s Set) First(f KeyFilter) Key {
	for _, k := range s {
		if f(k) {
			return k
		}
	}
	return nil
}

const (
	ParamKey = "keys"
)

func (s Set) MarshalJSON() ([]byte, error) {
	keys := make([]map[string]interface{}, len(s))

	for idx, k := range s {
		m := make(map[string]interface{})
		if err := k.marshalJSON(m); err != nil {
			return nil, err
		}
		keys[idx] = m
	}

	return json.Marshal(map[string]interface{}{
		ParamKey: keys,
	})
}
