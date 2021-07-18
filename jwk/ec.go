package jwk

import (
	"crypto/ecdsa"

	"github.com/halimath/jwx/internal/encoding"
)

// var supportedCurves = map[string]elliptic.Curve{
// 	"P-256": elliptic.P256(),
// 	"P-384": elliptic.P384(),
// 	"P-521": elliptic.P521(),
// }

// --

const (
	ParamCrv = "crv"
	ParamX   = "x"
	ParamY   = "y"
)

type ECDSAPublicKey struct {
	KeyDescription
	ecdsa.PublicKey
}

func (e *ECDSAPublicKey) Type() KeyType {
	return KeyTypeEC
}

func (e *ECDSAPublicKey) marshalJSON(data map[string]interface{}) error {
	data[ParamKeyType] = e.Type()

	e.KeyDescription.marshalJSON(data)

	data[ParamCrv] = e.PublicKey.Curve.Params().Name
	data[ParamX] = encoding.Encode(e.PublicKey.X.Bytes())
	data[ParamY] = encoding.Encode(e.PublicKey.Y.Bytes())

	return nil
}

var _ Key = &ECDSAPublicKey{}
