package jws

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	ALG_HS256 SignatureAlgorithm = "HS256"
	ALG_HS384 SignatureAlgorithm = "HS384"
	ALG_HS512 SignatureAlgorithm = "HS512"
)

// HMACSignerVerifier implements a signature method using a HMAC
// with a pre-shared secret.
type HMACSignerVerifier struct {
	h      func() hash.Hash
	secret []byte
	alg    SignatureAlgorithm
}

func (h *HMACSignerVerifier) Alg() SignatureAlgorithm {
	return h.alg
}

func (h *HMACSignerVerifier) Sign(data []byte) ([]byte, error) {
	mac := hmac.New(h.h, h.secret)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// HS256 creates a signature method implementing the HMAC SHA256 algorithm.
func HS256(secret []byte) SignerVerifier {
	return SymmetricSignature(&HMACSignerVerifier{
		h:      sha256.New,
		secret: secret,
		alg:    ALG_HS256,
	})
}

// HS384 creates a signature method implementing the HMAC SHA384 algorithm.
func HS384(secret []byte) SignerVerifier {
	return SymmetricSignature(&HMACSignerVerifier{
		h:      sha512.New384,
		secret: secret,
		alg:    ALG_HS384,
	})
}

// HS512 creates a signature method implementing the HMAC SHA512 algorithm.
func HS512(secret []byte) SignerVerifier {
	return SymmetricSignature(&HMACSignerVerifier{
		h:      sha512.New,
		secret: secret,
		alg:    ALG_HS512,
	})
}
