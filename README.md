# jwx

An implementation of JWS/JWK/JWT for [Go](https://golang.org)

![CI Status][ci-img-url] [![Go Report Card][go-report-card-img-url]][go-report-card-url] [![Package Doc][package-doc-img-url]][package-doc-url] [![Releases][release-img-url]][release-url]

This repo contains a module for the Golang programming language that provides an 
implementation for JSON Web Signature (JWS; 
[RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)), JSON Web Keys (JWK;
[RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) as well as JSON Web Tokens
(JWT; [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519)).

The module tries to provide an idiomatic Go API for creating, signing, decoding and verifying
JSON Web Tokens and exporting cryptographic keys in JSON Web Key standard. While this module
contains packages named `jwk`, `jws` and `jwt` these packages do not strictly adhere to the
content specified in the respective RFC. This is especially true for all the algorithms 
defined in [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) - JSON Web Algorithms - 
which are in part implemented in this module.

## Features

The following list summarizes the features provided by the this module.

* JWS
    * Sign and verify content using
        * HS256
        * HS384
        * HS512
        * RS256
        * RS384
        * RS512
        * ES256
        * ES384
        * ES512
* JWT
    * Sign and verify tokens using the above signature methods
    * Encode and decode claims standard claims
    * Encode and decode custom claims
    * Verify standard claims:
        * Issuer
        * Audience
        * Expires
        * Not before
        * Max age

## Installation

Use `go get` to install the libary with your project. You need Go >= 1.14 to use the lib.

```
$ go get github.com/halimath/jwx
```

## Usage

### JWT & JWS

The following code snippet shows how to create, sign, decode and verify a JWT using just
the standard claims of the spec. The example uses the `HS256` signature method which uses
as single, symmetric key to both sign and verify. 

```go
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

tokenDecoded, err := jwt.Decode(tokenInCompactSerialization)
if err != nil {
    panic(err)
}

if err := tokenDecoded.Verify(jwt.Signature(sig), jwt.ExpirationTime(time.Second)); err != nil {
    panic(err)
}
```

To run the code you need to add the following imports along with all the standard import:

```go
"github.com/halimath/jwx/jws"
"github.com/halimath/jwx/jwt"
```

A central type when using JWT is `jwt.Token`. A token is basically a `jws.JWS` which consists 
of a JOSE-header, a payload and a signature. In case of a `jwt.Token`, additional methods are
provided to interact with the payload which is known to be valid JSON. To create a `jwt.Token`
you can use one of the two functions:

* `jwt.Sign` which creates a token by applying a signer to the claims
* `jwt.Decode` which decodes a token from its _compact serialization_ which is the form most
  people associate with a JWT: three base64 encoded strings separated by dots.

Note that a decoded token is _not_ verified. This is a design intention which simplifies using
tokens which are known to be valid and safe to use. Decoding simply makes sure, that the given
string contains a valid token in compact serialization.

To verify a token you use the `Verify` method and pass a list of verifiers to apply. A 
`jwt.Verifier` is an interface type with a single `Verify` method. The package contains
implementations for most of the standard claims as well as the signature. You can also
create your own verifier and have them applied.

The following example shows how to create a token using custom claims and use a RSA key
pair to sign and verify the token.

```go
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
    panic(err)
}

signer := jws.RS256Signer(privateKey)

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

var c Claims
if err := token2.Claims(&c); err != nil {
    panic(err)
}

fmt.Printf("Full name: %s\n", c.Fullname)
```

Note that when using an asymmetric signature method (such as RSA or elliptic curves) you need
to create a signer and a verifier, which are different values. When using a symmetric method,
a single value implements both steps.

Also note that the example creates a custom type `Claims` to hold the token's claims. While
it is common that this type embeds `jwt.StandardClaims` it is not required. You can use 
whatever type you want as claims, as long as it can be marshaled to JSON using 
`encoding/json`. 

To unmarshal the token's payload into a custom claims value use the `token.Claims` method
which uses `encoding/json` under the hood.

## License

Copyright 2021 Alexander Metzner

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[ci-img-url]: https://github.com/halimath/jwx/workflows/CI/badge.svg
[go-report-card-img-url]: https://goreportcard.com/badge/github.com/halimath/jwx
[go-report-card-url]: https://goreportcard.com/report/github.com/halimath/jwx
[package-doc-img-url]: https://img.shields.io/badge/GoDoc-Reference-blue.svg
[package-doc-url]: https://pkg.go.dev/github.com/halimath/jwx
[release-img-url]: https://img.shields.io/github/v/release/halimath/jwx.svg
[release-url]: https://github.com/halimath/jwx/releases
