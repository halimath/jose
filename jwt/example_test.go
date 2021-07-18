package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/halimath/jwx/jws"
	"github.com/halimath/jwx/jwt"
)

func Example_standardClaimsWithHS256() {
	sig := jws.HS256([]byte("sh256-secret-key"))

	claims := jwt.StandardClaims{
		ID:      "17",
		Subject: "john.doe",
		Issuer:  "test",
		Audience: []string{
			"test",
			"anotherTest",
		},
		ExpirationTime: time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.Sign(sig, claims)
	if err != nil {
		panic(err)
	}

	tokenInCompactSerialization := token.Compact()

	fmt.Printf("JWT: %s\n", tokenInCompactSerialization)

	token2, err := jwt.Decode(tokenInCompactSerialization)
	if err != nil {
		panic(err)
	}

	if err := token2.Verify(jwt.Signature(sig), jwt.ExpirationTime(time.Second)); err != nil {
		panic(err)
	}

	fmt.Printf("Claims: %#v\n", token2.StandardClaims())
}

func Example_customClaimsWithHS256() {
	sig := jws.HS256([]byte("sh256-secret-key"))

	type Claims struct {
		jwt.StandardClaims
		Fullname string `json:"example.com/fullname"`
	}

	claims := Claims{
		StandardClaims: jwt.StandardClaims{
			ID:      "17",
			Subject: "john.doe",
			Issuer:  "test",
			Audience: []string{
				"test",
				"anotherTest",
			},
			ExpirationTime: time.Now().Add(time.Hour).Unix(),
		},
		Fullname: "John Doe",
	}

	token, err := jwt.Sign(sig, claims)
	if err != nil {
		panic(err)
	}

	tokenInCompactSerialization := token.Compact()

	token2, err := jwt.Decode(tokenInCompactSerialization)
	if err != nil {
		panic(err)
	}

	if err := token2.Verify(jwt.Signature(sig), jwt.ExpirationTime(time.Second)); err != nil {
		panic(err)
	}

	var c Claims
	if err := token2.Claims(&c); err != nil {
		panic(err)
	}

	fmt.Printf("Full name: %s\n", c.Fullname)

	// Output: Full name: John Doe
}

func Example_standardClaimsWithRS256() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	fmt.Println("Public key:")
	pem.Encode(os.Stdout, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})

	signer := jws.RS256Signer(privateKey)

	claims := jwt.StandardClaims{
		ID:      "17",
		Subject: "john.doe",
		Issuer:  "test",
		Audience: []string{
			"test",
			"anotherTest",
		},
		ExpirationTime: time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.Sign(signer, claims)
	if err != nil {
		panic(err)
	}

	tokenInCompactSerialization := token.Compact()

	fmt.Printf("JWT: %s\n", tokenInCompactSerialization)

	token2, err := jwt.Decode(tokenInCompactSerialization)
	if err != nil {
		panic(err)
	}

	verifier := jws.RS256Verifier(&privateKey.PublicKey)

	if err := token2.Verify(jwt.Signature(verifier), jwt.ExpirationTime(time.Second)); err != nil {
		panic(err)
	}

	fmt.Printf("Claims: %#v\n", token2.StandardClaims())
}

func Example_standardClaimsWithES256() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	fmt.Println("Public key:")

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	if err != nil {
		panic(err)
	}

	signer, err := jws.ES256Signer(privateKey)
	if err != nil {
		panic(err)
	}

	claims := jwt.StandardClaims{
		ID:      "17",
		Subject: "john.doe",
		Issuer:  "test",
		Audience: []string{
			"test",
			"anotherTest",
		},
		ExpirationTime: time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.Sign(signer, claims)
	if err != nil {
		panic(err)
	}

	tokenInCompactSerialization := token.Compact()

	fmt.Printf("JWT: %s\n", tokenInCompactSerialization)

	token2, err := jwt.Decode(tokenInCompactSerialization)
	if err != nil {
		panic(err)
	}

	verifier, err := jws.ES256Verifier(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	if err := token2.Verify(jwt.Signature(verifier), jwt.ExpirationTime(time.Second)); err != nil {
		panic(err)
	}

	fmt.Printf("Claims: %#v\n", token2.StandardClaims())
}
