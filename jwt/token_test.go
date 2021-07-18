package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/halimath/jwx/jws"
)

func TestStandardClaims_marshalling(t *testing.T) {
	now := time.Now().Unix()

	c := StandardClaims{
		ExpirationTime: now,
	}

	marshaled, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}

	var unmarshaled StandardClaims
	if err := json.Unmarshal(marshaled, &unmarshaled); err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(c, unmarshaled); diff != nil {
		t.Error(diff)
	}
}

func TestSign(t *testing.T) {
	token, err := Sign(jws.None(), StandardClaims{
		Subject:  "john.doe",
		Issuer:   "oauth-server",
		Audience: []string{"oauth-server-demo-app"},
	})

	if err != nil {
		t.Fatal(err)
	}

	if token.Compact() != "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJqb2huLmRvZSIsImlzcyI6Im9hdXRoLXNlcnZlciIsImF1ZCI6WyJvYXV0aC1zZXJ2ZXItZGVtby1hcHAiXX0." {
		t.Errorf("unexpected token: %#v", token)
	}
}

func TestDecode(t *testing.T) {
	token, err := Decode("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOlsib2F1dGgtc2VydmVyLWRlbW8tYXBwIl0sImlzcyI6Im9hdXRoLXNlcnZlciIsInN1YiI6ImpvaG4uZG9lIn0.")

	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(token.Header(), jws.Header{
		Algorithm: "none",
		Type:      "JWT",
	}); diff != nil {
		t.Error(diff)
	}

	if diff := deep.Equal(token.StandardClaims(), StandardClaims{
		Subject:  "john.doe",
		Issuer:   "oauth-server",
		Audience: []string{"oauth-server-demo-app"},
	}); diff != nil {
		t.Error(diff)
	}
}
