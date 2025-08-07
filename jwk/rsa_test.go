package jwk

import (
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/go-test/deep"
)

func TestRSAPublicKey_JSONSerialization(t *testing.T) {
	const jsonData = `{"use":"sig","kid":"1","kty":"RSA","n":"AQ","e":"Ag"}`

	t.Run("marshal", func(t *testing.T) {

		pk := &RSAPublicKey{
			KeyDescription: KeyDescription{
				KeyUse: UseSignature,
				KeyID:  "1",
			},
			PublicKey: &rsa.PublicKey{
				N: big.NewInt(1),
				E: 2,
			},
		}

		got, err := json.Marshal(pk)
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != jsonData {
			t.Errorf("expected\n%s but got\n%s", jsonData, string(got))
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		var pk RSAPublicKey

		if err := json.Unmarshal([]byte(jsonData), &pk); err != nil {
			t.Fatal(err)
		}

		want := RSAPublicKey{
			KeyDescription: KeyDescription{
				KeyUse: UseSignature,
				KeyID:  "1",
			},
			PublicKey: &rsa.PublicKey{
				N: big.NewInt(1),
				E: 2,
			},
		}

		if diff := deep.Equal(want, pk); diff != nil {
			t.Error(diff)
		}
	})
}
