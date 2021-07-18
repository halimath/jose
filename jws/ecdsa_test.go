package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestES256(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello, world")
	signer, err := ES256Signer(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := ES256Verifier(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifier.Verify(ALG_ES256, data, sig); err != nil {
		t.Error(err)
	}
}

func TestES384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello, world")
	signer, err := ES384Signer(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := ES384Verifier(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifier.Verify(ALG_ES384, data, sig); err != nil {
		t.Error(err)
	}
}

func TestES512(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello, world")
	signer, err := ES512Signer(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := ES512Verifier(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifier.Verify(ALG_ES512, data, sig); err != nil {
		t.Error(err)
	}
}
