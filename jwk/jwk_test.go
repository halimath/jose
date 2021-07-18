package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestSetJSON(t *testing.T) {
	set := Set{
		&ECDSAPublicKey{
			KeyDescription: KeyDescription{
				KeyUse: UseSignature,
				KeyID:  "1",
			},
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     big.NewInt(1),
				Y:     big.NewInt(2),
			},
		},
	}

	m, err := set.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	if string(m) != `{"keys":[{"crv":"P-256","kid":"1","kty":"EC","use":"sig","x":"AQ","y":"Ag"}]}` {
		t.Errorf("unexpected JSON: '%s'", string(m))
	}
}
