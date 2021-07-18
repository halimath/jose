package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	// RSASSA-PKCS1-v1_5 using SHA-256
	ALG_RS256 SignatureAlgorithm = "RS256"

	// RSASSA-PKCS1-v1_5 using SHA-384
	ALG_RS384 SignatureAlgorithm = "RS384"

	// RSASSA-PKCS1-v1_5 using SHA-512
	ALG_RS512 SignatureAlgorithm = "RS512"
)

// rsaSigner implements a signature signer using an RSASSA-PKCS1-v1_5 algorithm with
// SHA-2 based hashing as defined in RFC 7518 section 3.3
// (https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3)
type rsaSigner struct {
	alg        SignatureAlgorithm
	privateKey *rsa.PrivateKey
	h          crypto.Hash
	hf         func() hash.Hash
}

func (r *rsaSigner) Alg() SignatureAlgorithm {
	return r.alg
}

func (r *rsaSigner) Sign(data []byte) ([]byte, error) {
	h := r.hf()
	h.Write(data)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.privateKey, r.h, hashed)
}

// RS256Signer creates a new Signer using the RS256 algorithm as specified in
// RFC 7518 section 3.3
func RS256Signer(privateKey *rsa.PrivateKey) Signer {
	return &rsaSigner{
		alg:        ALG_RS256,
		privateKey: privateKey,
		h:          crypto.SHA256,
		hf:         sha256.New,
	}
}

// RS384Signer creates a new Signer using the RS384 algorithm as specified in
// RFC 7518 section 3.3
func RS384Signer(privateKey *rsa.PrivateKey) Signer {
	return &rsaSigner{
		alg:        ALG_RS384,
		privateKey: privateKey,
		h:          crypto.SHA384,
		hf:         sha512.New384,
	}
}

// RS512Signer creates a new Signer using the RS512 algorithm as specified in
// RFC 7518 section 3.3
func RS512Signer(privateKey *rsa.PrivateKey) Signer {
	return &rsaSigner{
		alg:        ALG_RS512,
		privateKey: privateKey,
		h:          crypto.SHA512,
		hf:         sha512.New,
	}
}

// --

// rsaVerifier implements a signature verifier using an RSASSA-PKCS1-v1_5 algorithm with
// SHA-2 based hashing as defined in RFC 7518 section 3.3
// (https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3)
type rsaVerifier struct {
	alg       SignatureAlgorithm
	publicKey *rsa.PublicKey
	h         crypto.Hash
	hf        func() hash.Hash
}

func (r *rsaVerifier) Verify(alg SignatureAlgorithm, data, signature []byte) error {
	h := r.hf()
	h.Write(data)
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.publicKey, r.h, hashed, signature)
}

// RS256Verifier creates a Verifier for RS256 as defined in RFC 7518 section 3.3
// (https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3)
func RS256Verifier(publicKey *rsa.PublicKey) Verifier {
	return &rsaVerifier{
		alg:       ALG_RS256,
		publicKey: publicKey,
		h:         crypto.SHA256,
		hf:        sha256.New,
	}
}

// RS384Verifier creates a Verifier for RS384 as defined in RFC 7518 section 3.3
// (https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3)
func RS384Verifier(publicKey *rsa.PublicKey) Verifier {
	return &rsaVerifier{
		alg:       ALG_RS384,
		publicKey: publicKey,
		h:         crypto.SHA384,
		hf:        sha512.New384,
	}
}

// RS512Verifier creates a Verifier for RS512 as defined in RFC 7518 section 3.3
// (https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3)
func RS512Verifier(publicKey *rsa.PublicKey) Verifier {
	return &rsaVerifier{
		alg:       ALG_RS512,
		publicKey: publicKey,
		h:         crypto.SHA512,
		hf:        sha512.New,
	}
}
