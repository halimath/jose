package jose_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/halimath/jose/jwk"
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

		secretData, err := os.ReadFile("./testdata/secret.json")
		if err != nil {
			t.Fatal(err)
		}
		key, err := jwk.UnmarshalKey(secretData)

		symmertricKey, ok := key.(*jwk.SymmetricKey)
		if !ok {
			t.Fatalf("not a symmertric key: %v", key)
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

				signerVerifier, err := jws.HSSignerVerifier(alg, symmertricKey.Bytes)
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
		var publicKey *rsa.PublicKey
		if err := loadPublicKey("./testdata/rsa.public.pem", &publicKey); err != nil {
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
				var publicKey *ecdsa.PublicKey
				if err := loadPublicKey(fmt.Sprintf("./testdata/%s.public.pem", strings.ToLower(string(alg))), &publicKey); err != nil {
					t.Fatal(err)
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

func loadPublicKey[K crypto.PublicKey](filename string, publicKey **K) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(data)
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	var ok bool
	*publicKey, ok = pubInterface.(*K)
	if !ok {
		return fmt.Errorf("public key is not of type %T: %v", publicKey, pubInterface)
	}

	return nil
}
