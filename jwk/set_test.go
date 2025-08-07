package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/go-test/deep"
)

func TestSet_JSONSerialization(t *testing.T) {
	const jsonData = `{"keys":[{"use":"sig","kid":"1","kty":"EC","crv":"P-256","x":"AQ","y":"Ag"},{"use":"sig","kid":"1","kty":"RSA","n":"AQ","e":"Ag"},{"kty":"oct","k":"czNjcjN0"}]}`
	set := Set{
		&ECDSAPublicKey{
			KeyDescription: KeyDescription{
				KeyUse: UseSignature,
				KeyID:  "1",
			},
			PublicKey: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     big.NewInt(1),
				Y:     big.NewInt(2),
			},
		},
		&RSAPublicKey{
			KeyDescription: KeyDescription{
				KeyUse: UseSignature,
				KeyID:  "1",
			},
			PublicKey: &rsa.PublicKey{
				N: big.NewInt(1),
				E: 2,
			},
		},
		&SymmetricKey{
			Bytes: []byte("s3cr3t"),
		},
	}

	t.Run("marshal", func(t *testing.T) {
		got, err := json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != jsonData {
			t.Errorf("want\n%s but got\n%s", jsonData, string(got))
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		var got Set

		if err := json.Unmarshal([]byte(jsonData), &got); err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(set, got); diff != nil {
			t.Errorf("want\n%+v but got\n%+v", set, got)
		}
	})
}
