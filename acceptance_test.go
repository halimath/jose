package jose_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/halimath/jose/jws"
	"github.com/halimath/jose/jwt"
)

func TestVerifyJWT(t *testing.T) {
	t.Run("HMAC", func(t *testing.T) {
		algs := []jws.SignatureAlgorithm{
			jws.ALG_HS256,
			jws.ALG_HS384,
			jws.ALG_HS512,
		}

		secret, err := os.ReadFile("./testdata/secret")
		if err != nil {
			t.Fatal(err)
		}

		for _, alg := range algs {
			t.Run(string(alg), func(t *testing.T) {
				compact, err := os.ReadFile("./testdata/jwt." + strings.ToLower(string(alg)))
				if err != nil {
					t.Fatal(err)
				}

				token, err := jwt.Decode(string(compact))
				if err != nil {
					t.Fatal(err)
				}

				signerVerifier, err := jws.HSSignerVerifier(alg, secret)
				if err != nil {
					t.Fatal(err)
				}

				err = token.Verify(
					jwt.Issuer("github.com/halimath/jose"),
					jwt.Audience("github.com/halimath/jose"),
					jwt.ExpirationTime(time.Second),
					jwt.NotBefore(time.Second),
					jwt.MaxAge(24*365*10*time.Hour),
					jwt.Signature(signerVerifier),
				)
				if err != nil {
					t.Error(err)
				}
			})
		}
	})

	t.Run("RSA", func(t *testing.T) {
		algs := []jws.SignatureAlgorithm{
			jws.ALG_RS256,
			jws.ALG_RS512,
		}

		// TODO: Replace key loading with JWK related stuff once implemented
		publicKeyBytes, err := os.ReadFile("./testdata/rsa.public.pem")
		if err != nil {
			t.Fatal(err)
		}

		block, _ := pem.Decode(publicKeyBytes)
		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		publicKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("not a RSA public key: %+v", pubInterface)
		}

		for _, alg := range algs {
			t.Run(string(alg), func(t *testing.T) {
				compact, err := os.ReadFile("./testdata/jwt." + strings.ToLower(string(alg)))
				if err != nil {
					t.Fatal(err)
				}

				token, err := jwt.Decode(string(compact))
				if err != nil {
					t.Fatal(err)
				}

				verifier, err := jws.RSVerifier(alg, publicKey)
				if err != nil {
					t.Fatal(err)
				}

				err = token.Verify(
					jwt.Issuer("github.com/halimath/jose"),
					jwt.Audience("github.com/halimath/jose"),
					jwt.ExpirationTime(time.Second),
					jwt.NotBefore(time.Second),
					jwt.MaxAge(24*365*10*time.Hour),
					jwt.Signature(verifier),
				)
				if err != nil {
					t.Error(err)
				}
			})
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		algs := []jws.SignatureAlgorithm{
			jws.ALG_ES256,
			jws.ALG_ES512,
		}

		for _, alg := range algs {
			t.Run(string(alg), func(t *testing.T) {
				// TODO: Replace key loading with JWK related stuff once implemented
				publicKeyBytes, err := os.ReadFile(fmt.Sprintf("./testdata/%s.public.pem", strings.ToLower(string(alg))))
				if err != nil {
					t.Fatal(err)
				}

				block, _ := pem.Decode(publicKeyBytes)
				pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				publicKey, ok := pubInterface.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("not a ECDSA public key: %+v", pubInterface)
				}

				compact, err := os.ReadFile("./testdata/jwt." + strings.ToLower(string(alg)))
				if err != nil {
					t.Fatal(err)
				}

				token, err := jwt.Decode(string(compact))
				if err != nil {
					t.Fatal(err)
				}

				verifier, err := jws.ESVerifier(alg, publicKey)
				if err != nil {
					t.Fatal(err)
				}

				err = token.Verify(
					jwt.Issuer("github.com/halimath/jose"),
					jwt.Audience("github.com/halimath/jose"),
					jwt.ExpirationTime(time.Second),
					jwt.NotBefore(time.Second),
					jwt.MaxAge(24*365*10*time.Hour),
					jwt.Signature(verifier),
				)
				if err != nil {
					t.Error(err)
				}
			})
		}
	})

}
