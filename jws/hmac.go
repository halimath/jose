package jws

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
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

// HSSignerVerifier creates a new HMAC based SignerVerifier using alg as the
// HMAC algorithm and secret as the HMAC secret. If alg does not describe an
// HMAC algorithm (i.e. ES256 or RS256) a non-nil error is returned.
func HSSignerVerifier(alg SignatureAlgorithm, secret []byte) (SignerVerifier, error) {
	switch alg {
	case ALG_HS256:
		return HS256(secret), nil
	case ALG_HS384:
		return HS384(secret), nil
	case ALG_HS512:
		return HS512(secret), nil
	default:
		return nil, fmt.Errorf("unsupported HMAC signature algorithm: %s", alg)
	}
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
