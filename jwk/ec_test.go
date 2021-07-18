package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/go-test/deep"
)

func TestECDSAPublicKey(t *testing.T) {
	pk := ECDSAPublicKey{
		KeyDescription: KeyDescription{
			KeyUse: UseSignature,
			KeyID:  "1",
		},
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(1),
			Y:     big.NewInt(2),
		},
	}

	act := make(map[string]interface{})
	if err := pk.marshalJSON(act); err != nil {
		t.Fatal(err)
	}

	exp := map[string]interface{}{
		ParamKeyType: KeyTypeEC,
		ParamUse:     UseSignature,
		ParamKID:     "1",
		ParamCrv:     "P-256",
		ParamX:       "AQ",
		ParamY:       "Ag",
	}

	if diff := deep.Equal(exp, act); diff != nil {
		t.Error(diff)
	}
}
