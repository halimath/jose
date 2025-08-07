package jwk

import (
	"encoding/json"
	"fmt"
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

// KeyOp defines the types of key operations as specified in RFC 7517 section 4.3
// (https://datatracker.ietf.org/doc/html/rfc7517#section-4.3)
type KeyOp string

const (
	// Parameter "key_ops" for encoding the key operations
	ParamKeyOps = "key_ops"

	// compute digital signature or MAC
	KeyOpsSign KeyOp = "sign"

	// verify digital signature or MAC
	KeyOpsVerify KeyOp = "verify"

	// encrypt content
	KeyOpsEncrypt KeyOp = "encrypt"

	// decrypt content and validate decryption, if applicable
	KeyOpsDecrypt KeyOp = "decrypt"

	// encrypt key
	KeyOpsKeyWrap KeyOp = "wrapKey"

	// decrypt key and validate decryption, if applicable
	KeyOpsUnwrapKey KeyOp = "unwrapKey"

	// derive key
	KeyOpsDeriveKey KeyOp = "deriveKey"

	// derive bits not to be used as a key
	KeyOpsDeriveBits KeyOp = "deriveBits"
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
	Operations() []KeyOp

	// The "alg" parameter
	Algorithm() string

	// The "kid" parameter
	ID() string
}

// MarshalKey marshals k into a JWK representation and returns the JSON bytes
// as well as any error occured during marshaling. This is essentially just
// a wrapper for json.Marshal. It is provided here as a symmetric API to
// UnmarshalKey, which returns dynamic types.
func MarshalKey(k Key) ([]byte, error) {
	return json.Marshal(k)
}

// UnmarshalKey unmarshals JSON data as a JWK Key and returns an appropriate
// type depending on the kty and other attributes. Any error during unmarshaling
// as well as unsupported key types lead to an error being returned.
func UnmarshalKey(data []byte) (Key, error) {
	type keyWrapper struct {
		Type KeyType `json:"kty"`
		// TODO: We need something like "d" to distinguish public from private keys
	}

	var kw keyWrapper
	if err := json.Unmarshal(data, &kw); err != nil {
		return nil, err
	}

	switch kw.Type {
	case KeyTypeEC:
		var k ECDSAPublicKey
		if err := json.Unmarshal(data, &k); err != nil {
			return nil, err
		}
		return &k, nil

	case KeyTypeRSA:
		var k RSAPublicKey
		if err := json.Unmarshal(data, &k); err != nil {
			return nil, err
		}

		return &k, nil

	case KeyTypeOct:
		var k SymmetricKey
		if err := json.Unmarshal(data, &k); err != nil {
			return nil, err
		}

		return &k, nil

	default:
		return nil, fmt.Errorf("unsupported kty: %s", kw.Type)
	}
}

// KeyDescription provides a simple struct that implements
// the generic getters defined by Key. It is included in
// each key's struct definition and allows the values to
// be set.
type KeyDescription struct {
	KeyUse        KeyUse  `json:"use,omitempty"`
	KeyOperations []KeyOp `json:"ops,omitempty"`
	KeyAlgorithm  string  `json:"alg,omitempty"`
	KeyID         string  `json:"kid,omitempty"`
}

func (k *KeyDescription) Use() KeyUse {
	return k.KeyUse
}

func (k *KeyDescription) Operations() []KeyOp {
	return k.KeyOperations
}

func (k *KeyDescription) Algorithm() string {
	return k.KeyAlgorithm
}

func (k *KeyDescription) ID() string {
	return k.KeyID
}
