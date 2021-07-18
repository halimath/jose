package jws

import (
	"encoding/base64"
	"testing"
)

func TestHS256(t *testing.T) {
	sm := HS256([]byte("secret"))

	if sm.Alg() != ALG_HS256 {
		t.Error(sm.Alg())
	}

	data := []byte("hello, world")
	sig, err := sm.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	s := enc.EncodeToString(sig)
	if s != "cLVE7E3Y71-ng0_laMdt9fPPdbb93vE9eeJCjoda21s" {
		t.Error(s)
	}

	if err := sm.Verify(ALG_HS256, data, sig); err != nil {
		t.Error(err)
	}
}
func TestHS384(t *testing.T) {
	sm := HS384([]byte("secret"))

	if sm.Alg() != ALG_HS384 {
		t.Error(sm.Alg())
	}

	data := []byte("hello, world")
	sig, err := sm.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	s := enc.EncodeToString(sig)
	if s != "rbpnoLvkKLTH5g1uwzcxZR1RGcZPFqmf8q8JDNqkFd8lb0vwjB82gpEUASgpUUrk" {
		t.Error(s)
	}

	if err := sm.Verify(ALG_HS384, data, sig); err != nil {
		t.Error(err)
	}
}

func TestHS512(t *testing.T) {
	sm := HS512([]byte("secret"))

	if sm.Alg() != ALG_HS512 {
		t.Error(sm.Alg())
	}

	data := []byte("hello, world")
	sig, err := sm.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	s := enc.EncodeToString(sig)
	if s != "WPnGrZvqfmLl32zJvZ5NQFkr-QCo0rsJe0yfx8G6imLQLKA3UoJ1ICxj8S6yQawv8-pmeFrw70FULkz2Bome9Q" {
		t.Error(s)
	}

	if err := sm.Verify(ALG_HS512, data, sig); err != nil {
		t.Error(err)
	}
}

var enc = base64.URLEncoding.WithPadding(base64.NoPadding)
