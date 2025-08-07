package jwk

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/halimath/jose/internal/encoding"
)

type RSAPublicKey struct {
	KeyDescription
	*rsa.PublicKey
}

func (e *RSAPublicKey) Type() KeyType {
	return KeyTypeRSA
}

type rsaPublicKeyJSONWrapper struct {
	KeyDescription
	Type KeyType `json:"kty"`
	N    string  `json:"n"`
	E    string  `json:"e"`
}

func (e *RSAPublicKey) MarshalJSON() ([]byte, error) {
	w := rsaPublicKeyJSONWrapper{
		KeyDescription: e.KeyDescription,
		Type:           e.Type(),
		N:              encoding.Encode(e.PublicKey.N.Bytes()),
		E:              encoding.Encode(big.NewInt(int64(e.PublicKey.E)).Bytes()),
	}

	return json.Marshal(w)
}

func (e *RSAPublicKey) UnmarshalJSON(data []byte) error {
	var w rsaPublicKeyJSONWrapper

	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}

	if w.Type != KeyTypeRSA {
		return fmt.Errorf("invalid key type: %s", w.Type)
	}

	nBytes, err := encoding.Decode(w.N)
	if err != nil {
		return fmt.Errorf("invalid x value: %v", err)
	}

	eBytes, err := encoding.Decode(w.E)
	if err != nil {
		return fmt.Errorf("invalid y value: %v", err)
	}

	e.KeyDescription = w.KeyDescription
	e.PublicKey = &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(nBytes),
		E: int(big.NewInt(0).SetBytes(eBytes).Int64()),
	}

	return nil
}
