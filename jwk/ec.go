package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/halimath/jose/internal/encoding"
)

type ECDSAPublicKey struct {
	KeyDescription
	*ecdsa.PublicKey
}

func (e *ECDSAPublicKey) Type() KeyType {
	return KeyTypeEC
}

type ecdsaPublicKeyJSONWrapper struct {
	KeyDescription
	Type  KeyType `json:"kty"`
	Curve string  `json:"crv"`
	X     string  `json:"x"`
	Y     string  `json:"y"`
}

func (e *ECDSAPublicKey) MarshalJSON() ([]byte, error) {
	w := ecdsaPublicKeyJSONWrapper{
		KeyDescription: e.KeyDescription,
		Type:           e.Type(),
		Curve:          e.Params().Params().Name,
		X:              encoding.Encode(e.PublicKey.X.Bytes()),
		Y:              encoding.Encode(e.PublicKey.Y.Bytes()),
	}

	return json.Marshal(w)
}

var supportedCurves = map[string]elliptic.Curve{
	"P-256": elliptic.P256(),
	"P-384": elliptic.P384(),
	"P-521": elliptic.P521(),
}

func (e *ECDSAPublicKey) UnmarshalJSON(data []byte) error {
	var w ecdsaPublicKeyJSONWrapper

	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}

	if w.Type != KeyTypeEC {
		return fmt.Errorf("invalid key type: %s", w.Type)
	}

	crv, ok := supportedCurves[w.Curve]
	if !ok {
		return fmt.Errorf("invalid EC curve: %s", w.Curve)
	}

	xBytes, err := encoding.Decode(w.X)
	if err != nil {
		return fmt.Errorf("invalid x value: %v", err)
	}

	yBytes, err := encoding.Decode(w.Y)
	if err != nil {
		return fmt.Errorf("invalid y value: %v", err)
	}

	e.KeyDescription = w.KeyDescription
	e.PublicKey = &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(xBytes),
		Y:     big.NewInt(0).SetBytes(yBytes),
	}

	return nil
}
