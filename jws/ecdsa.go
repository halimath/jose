package jws

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"
)

const (
	// ECDSA using P-256 and SHA-256
	ALG_ES256 SignatureAlgorithm = "ES256"

	// ECDSA using P-384 and SHA-384
	ALG_ES384 SignatureAlgorithm = "ES384"

	// ECDSA using P-521 and SHA-512
	ALG_ES512 SignatureAlgorithm = "ES512"
)

// ecdsaSigner implements a signature signer using an ECDSA algorithm with
// SHA-2 based hashing as defined in RFC 7518 section 3.4
// (https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)
type ecdsaSigner struct {
	alg        SignatureAlgorithm
	privateKey *ecdsa.PrivateKey
	hf         func() hash.Hash
	keyBitSize int
}

func (e *ecdsaSigner) Alg() SignatureAlgorithm {
	return e.alg
}

func (e *ecdsaSigner) Sign(data []byte) ([]byte, error) {
	h := e.hf()
	h.Write(data)
	hashed := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, hashed)
	if err != nil {
		return nil, err
	}

	keyBytes := e.keyBitSize / 8
	if e.keyBitSize%8 > 0 {
		keyBytes++
	}

	out := make([]byte, 2*keyBytes)

	rBytes := r.Bytes()
	copy(out[keyBytes-len(rBytes):], rBytes)
	sBytes := s.Bytes()
	copy(out[keyBytes+keyBytes-len(sBytes):], sBytes)

	return out, nil
}

// ES256Signer creates a Signer providing ECDSA using P-256 and SHA-256
// signatures using the given private key which must use
// ellipctic.P256() as the underlying curve.
func ES256Signer(privateKey *ecdsa.PrivateKey) (Signer, error) {
	if privateKey.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("invalid key: must use elliptic curve key with curve bit size of 256")
	}

	return &ecdsaSigner{
		alg:        ALG_ES256,
		privateKey: privateKey,
		hf:         sha256.New,
		keyBitSize: 256,
	}, nil
}

// ES384Signer creates a Signer providing ECDSA using P-384 and SHA-384
// signatures using the given private key which must use
// ellipctic.P384() as the underlying curve.
func ES384Signer(privateKey *ecdsa.PrivateKey) (Signer, error) {
	if privateKey.Curve.Params().BitSize != 384 {
		return nil, fmt.Errorf("invalid key: must use elliptic curve key with curve bit size of 384")
	}

	return &ecdsaSigner{
		alg:        ALG_ES384,
		privateKey: privateKey,
		hf:         sha512.New384,
		keyBitSize: 384,
	}, nil
}

// ES512Signer creates a Signer providing ECDSA using P-512 and SHA-512
// signatures using the given private key which must use
// ellipctic.P512() as the underlying curve.
func ES512Signer(privateKey *ecdsa.PrivateKey) (Signer, error) {
	if privateKey.Curve.Params().BitSize != 521 {
		return nil, fmt.Errorf("invalid key: must use elliptic curve key with curve bit size of 521")
	}

	return &ecdsaSigner{
		alg:        ALG_ES512,
		privateKey: privateKey,
		hf:         sha512.New,
		keyBitSize: 521,
	}, nil
}

type ecdsaVerifier struct {
	alg        SignatureAlgorithm
	publicKey  *ecdsa.PublicKey
	hf         func() hash.Hash
	keyBitSize int
}

func (e *ecdsaVerifier) Verify(alg SignatureAlgorithm, data, signature []byte) error {
	if alg != e.alg {
		return fmt.Errorf("%w: %s", ErrInvalidSignature, "invalid algorithm")
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

	n := len(signature) / 2
	r.SetBytes(signature[:n])
	s.SetBytes(signature[n:])

	h := e.hf()
	h.Write(data)
	hashed := h.Sum(nil)

	ok := ecdsa.Verify(e.publicKey, hashed, r, s)
	if !ok {
		return ErrInvalidSignature
	}

	return nil
}

// ES256Verifier creates a Verifier verifying ECDSA using P-256 and SHA-256
// signatures using the given public key which must use
// ellipctic.P256() as the underlying curve.
func ES256Verifier(publicKey *ecdsa.PublicKey) (Verifier, error) {
	if publicKey.Params().BitSize != 256 {
		return nil, fmt.Errorf("invalid key: must use elliptic curve key with curve bit size of 256")
	}

	return &ecdsaVerifier{
		alg:        ALG_ES256,
		publicKey:  publicKey,
		hf:         sha256.New,
		keyBitSize: 256,
	}, nil
}

// ES384Verifier creates a Verifier verifying ECDSA using P-384 and SHA-384
// signatures using the given public key which must use
// ellipctic.P384() as the underlying curve.
func ES384Verifier(publicKey *ecdsa.PublicKey) (Verifier, error) {
	if publicKey.Params().BitSize != 384 {
		return nil, fmt.Errorf("invalid key: must use elliptic curve key with curve bit size of 384")
	}

	return &ecdsaVerifier{
		alg:        ALG_ES384,
		publicKey:  publicKey,
		hf:         sha512.New384,
		keyBitSize: 384,
	}, nil
}

// ES512Verifier creates a Verifier verifying ECDSA using P-512 and SHA-512
// signatures using the given public key which must use
// ellipctic.P512() as the underlying curve.
func ES512Verifier(publicKey *ecdsa.PublicKey) (Verifier, error) {
	if publicKey.Params().BitSize != 521 {
		return nil, fmt.Errorf("invalid key: must use elliptic curve key with curve bit size of 521")
	}

	return &ecdsaVerifier{
		alg:        ALG_ES512,
		publicKey:  publicKey,
		hf:         sha512.New,
		keyBitSize: 521,
	}, nil
}
