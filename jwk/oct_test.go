package jwk

import (
	"encoding/json"
	"testing"

	"github.com/go-test/deep"
)

func TestSymmetricKey_jsonMarshaling(t *testing.T) {
	key := SymmetricKey{
		Bytes: []byte("s3cr3t"),
	}

	const jsonString = `{"kty":"oct","k":"czNjcjN0"}`

	t.Run("marshal", func(t *testing.T) {
		data, err := json.Marshal(&key)

		if err != nil {
			t.Fatal(err)
		}

		if string(data) != jsonString {
			t.Errorf("expected\n%s but got\n%s", jsonString, string(data))
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		var unmarshaled SymmetricKey
		err := json.Unmarshal([]byte(jsonString), &unmarshaled)
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(key, unmarshaled); diff != nil {
			t.Errorf("unexpected diff %v", diff)
		}
	})
}
