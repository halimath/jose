package jws

import (
	"testing"

	"github.com/go-test/deep"
)

func TestHeader(t *testing.T) {
	h := Header{
		Algorithm: "none",
		Type:      "JWT",
	}

	encoded := h.Encode()
	decoded, err := DecodeHeader(encoded)

	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(h, *decoded); diff != nil {
		t.Error(diff)
	}
}

func TestSignParseVerify(t *testing.T) {
	sig := None()
	j, err := Sign(sig, []byte("hello, world"), Header{})
	if err != nil {
		t.Fatal(err)
	}

	c := j.Compact()

	if c != "eyJhbGciOiJub25lIn0.aGVsbG8sIHdvcmxk." {
		t.Error(c)
	}

	j2, err := ParseCompact(c)

	if err != nil {
		t.Fatal(err)
	}

	if err := j.VerifySignature(sig); err != nil {
		t.Error(err)
	}

	if diff := deep.Equal(j, j2); diff != nil {
		t.Error(diff)
	}
}

func TestNone(t *testing.T) {
	sm := None()

	if sm.Alg() != ALG_NONE {
		t.Error(sm.Alg())
	}

	data := []byte("hello, world")

	sig, err := sm.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	s := enc.EncodeToString(sig)
	if s != "" {
		t.Error(s)
	}

	if err := sm.Verify(ALG_NONE, data, sig); err != nil {
		t.Error(err)
	}
}
