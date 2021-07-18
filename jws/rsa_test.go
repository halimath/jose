package jws

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestRS256(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer := RS256Signer(privateKey)

	if signer.Alg() != ALG_RS256 {
		t.Error(signer.Alg())
	}

	data := []byte("hello, world")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	verifier := RS256Verifier(&privateKey.PublicKey)

	if err := verifier.Verify(ALG_HS256, data, sig); err != nil {
		t.Error(err)
	}
}

func TestRS384(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer := RS384Signer(privateKey)

	if signer.Alg() != ALG_RS384 {
		t.Error(signer.Alg())
	}

	data := []byte("hello, world")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	verifier := RS384Verifier(&privateKey.PublicKey)

	if err := verifier.Verify(ALG_HS384, data, sig); err != nil {
		t.Error(err)
	}
}

func TestRS512(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer := RS512Signer(privateKey)

	if signer.Alg() != ALG_RS512 {
		t.Error(signer.Alg())
	}

	data := []byte("hello, world")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	verifier := RS512Verifier(&privateKey.PublicKey)

	if err := verifier.Verify(ALG_HS512, data, sig); err != nil {
		t.Error(err)
	}
}
