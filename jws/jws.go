// Package jws contains implementations of the JSON Web Signatures (jws) defined
// in RFC 7517 (https://datatracker.ietf.org/doc/html/rfc7517) as well as parts
// from JSON Web Algorithms (jwa) as defined in RFC 7518
// (https://www.rfc-editor.org/rfc/rfc7518.html)
package jws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/halimath/jose/internal/encoding"
)

var (
	// ErrInvalidCompactJWS is returned when a given string is not a valid JWS in compact serialized form.
	ErrInvalidCompactJWS = errors.New("invalid compact JWS")

	ErrInvalidHeader = errors.New("invalid header")
)

// --

// Header defines the structure representing a JWS JOSE header as defined in RFC7515 section 4
// (https://datatracker.ietf.org/doc/html/rfc7515#section-4). This implementation has no support
// for private header parameters.
type Header struct {
	Algorithm SignatureAlgorithm `json:"alg"`
	Type      string             `json:"typ,omitempty"`

	// TODO: Add standard fields
	// 	4.1.2.  "jku" (JWK Set URL) Header Parameter

	// 	The "jku" (JWK Set URL) Header Parameter is a URI [RFC3986] that
	// 	refers to a resource for a set of JSON-encoded public keys, one of
	// 	which corresponds to the key used to digitally sign the JWS.  The
	// 	keys MUST be encoded as a JWK Set [JWK].  The protocol used to
	// 	acquire the resource MUST provide integrity protection; an HTTP GET
	// 	request to retrieve the JWK Set MUST use Transport Layer Security
	//  	(TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be
	// 	validated, as per Section 6 of RFC 6125 [RFC6125].  Also, see
	// 	Section 8 on TLS requirements.  Use of this Header Parameter is
	// 	OPTIONAL.

	//  4.1.3.  "jwk" (JSON Web Key) Header Parameter

	// 	The "jwk" (JSON Web Key) Header Parameter is the public key that
	// 	corresponds to the key used to digitally sign the JWS.  This key is
	// 	represented as a JSON Web Key [JWK].  Use of this Header Parameter is
	// 	OPTIONAL.

	//  4.1.4.  "kid" (Key ID) Header Parameter

	// 	The "kid" (key ID) Header Parameter is a hint indicating which key
	// 	was used to secure the JWS.  This parameter allows originators to
	// 	explicitly signal a change of key to recipients.  The structure of
	// 	the "kid" value is unspecified.  Its value MUST be a case-sensitive
	// 	string.  Use of this Header Parameter is OPTIONAL.

	// 	When used with a JWK, the "kid" value is used to match a JWK "kid"
	// 	parameter value.

	//  4.1.5.  "x5u" (X.509 URL) Header Parameter

	// 	The "x5u" (X.509 URL) Header Parameter is a URI [RFC3986] that refers
	// 	to a resource for the X.509 public key certificate or certificate
	// 	chain [RFC5280] corresponding to the key used to digitally sign the
	// 	JWS.  The identified resource MUST provide a representation of the
	// 	certificate or certificate chain that conforms to RFC 5280 [RFC5280]
	// 	in PEM-encoded form, with each certificate delimited as specified in
	// 	Section 6.1 of RFC 4945 [RFC4945].  The certificate containing the
	// 	public key corresponding to the key used to digitally sign the JWS
	// 	MUST be the first certificate.  This MAY be followed by additional
	// 	certificates, with each subsequent certificate being the one used to
	// 	certify the previous one.  The protocol used to acquire the resource
	// 	MUST provide integrity protection; an HTTP GET request to retrieve
	// 	the certificate MUST use TLS [RFC2818] [RFC5246]; and the identity of
	// 	the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].
	// 	Also, see Section 8 on TLS requirements.  Use of this Header
	// 	Parameter is OPTIONAL.

	//  4.1.6.  "x5c" (X.509 Certificate Chain) Header Parameter

	// 	The "x5c" (X.509 certificate chain) Header Parameter contains the
	// 	X.509 public key certificate or certificate chain [RFC5280]
	// 	corresponding to the key used to digitally sign the JWS.  The
	// 	certificate or certificate chain is represented as a JSON array of
	// 	certificate value strings.  Each string in the array is a
	// 	base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
	// 	[ITU.X690.2008] PKIX certificate value.  The certificate containing
	// 	the public key corresponding to the key used to digitally sign the
	// 	JWS MUST be the first certificate.  This MAY be followed by
	// 	additional certificates, with each subsequent certificate being the
	// 	one used to certify the previous one.  The recipient MUST validate
	// 	the certificate chain according to RFC 5280 [RFC5280] and consider
	// 	the certificate or certificate chain to be invalid if any validation
	// 	failure occurs.  Use of this Header Parameter is OPTIONAL.

	// 	See Appendix B for an example "x5c" value.

	//  4.1.7.  "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter

	// 	The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
	// 	base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
	// 	encoding of the X.509 certificate [RFC5280] corresponding to the key
	// 	used to digitally sign the JWS.  Note that certificate thumbprints
	// 	are also sometimes known as certificate fingerprints.  Use of this
	// 	Header Parameter is OPTIONAL.

	//  4.1.8.  "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
	// 		 Parameter

	// 	The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header
	// 	Parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
	// 	of the DER encoding of the X.509 certificate [RFC5280] corresponding
	// 	to the key used to digitally sign the JWS.  Note that certificate
	// 	thumbprints are also sometimes known as certificate fingerprints.
	// 	Use of this Header Parameter is OPTIONAL.
}

func (h *Header) Encode() string {
	b, err := json.Marshal(*h)
	if err != nil {
		panic(err)
	}

	return encoding.Encode(b)
}

func DecodeHeader(encoded string) (*Header, error) {
	b, err := encoding.Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidHeader, err)
	}

	var h Header
	err = json.Unmarshal(b, &h)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidHeader, err)
	}

	return &h, nil
}

// --

// JWS implements a JSON Web Signature datastructure. The fields
// of this struct represent the different components of a JWS in
// multiple ways. Once created a JWS is immutable. A JWS may only
// be created through functions exposed from this package, i.e.
// 		func Sign(signatureMethod SignatureMethod, payload []byte, header Header) JWS
// 		func ParseCompact(compact string) (*JWS, error)
type JWS struct {
	header           Header
	headerEncoded    string
	payload          []byte
	payloadEncoded   string
	signature        []byte
	signatureEncoded string
}

// Header returns a copy of j's header.
func (j *JWS) Header() Header {
	return j.header
}

// Payload returns a deep copy of j's payload.
func (j *JWS) Payload() []byte {
	b := make([]byte, len(j.payload))
	copy(b, j.payload)
	return b
}

// Compact returns the JWS in compact serialization as specified in
// RFC 7515 section 7.1
// (https://datatracker.ietf.org/doc/html/rfc7515#section-7.1)
func (j *JWS) Compact() string {
	return j.headerEncoded + "." + j.payloadEncoded + "." + j.signatureEncoded
}

var (
	// ErrInvalidSignature is returned from VerifySignature when the signature is not considered valid.
	ErrInvalidSignature = errors.New("invalid signature")
)

// Verify verifies that the signature t carries has zero length.
func (j *JWS) VerifySignature(verifier Verifier) error {
	if err := verifier.Verify(j.header.Algorithm, []byte(j.headerEncoded+"."+j.payloadEncoded), j.signature); err != nil {
		return fmt.Errorf("%w: invalid signature bytes", ErrInvalidSignature)
	}

	return nil
}

// Sign signs the given payload and header with the given signature method.
// It returns a JWS value containing the raw and encoded parts as well as
// the signature.
func Sign(signer Signer, payload []byte, header Header) (*JWS, error) {
	header.Algorithm = signer.Alg()
	headerEncoded := header.Encode()
	payloadEncoded := encoding.Encode(payload)

	signature, err := signer.Sign([]byte(headerEncoded + "." + payloadEncoded))
	if err != nil {
		return nil, err
	}

	return &JWS{
		header:           header,
		headerEncoded:    headerEncoded,
		payload:          payload,
		payloadEncoded:   payloadEncoded,
		signature:        signature,
		signatureEncoded: encoding.Encode(signature),
	}, nil
}

// ParseCompact parses the given compact representation into a JWS datastructure and returns it.
// It performs only a syntactically validation of base64 URL encoded data as well as parsing
// the JOSE header JSON. The signature ist NOT verified. Use Verify to perform the verification.
func ParseCompact(compact string) (*JWS, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: invalid number of encoded parts", ErrInvalidCompactJWS)
	}

	header, err := DecodeHeader(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCompactJWS, err)
	}

	payload, err := encoding.Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCompactJWS, err)
	}

	signature, err := encoding.Decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCompactJWS, err)
	}

	return &JWS{
		header:           *header,
		headerEncoded:    parts[0],
		payload:          payload,
		payloadEncoded:   parts[1],
		signature:        signature,
		signatureEncoded: parts[2],
	}, nil
}

// SignatureAlgorithm defines the type used to name algorithms creating
// digital signature including MACs.
type SignatureAlgorithm string

// Signer defines the interface for types implementing
// a given signature method for signing byte slices.
type Signer interface {
	// Alg returns the name of the signature algorithm as defined in
	// RFC 7518 section 3.1
	// (https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1)
	Alg() SignatureAlgorithm

	// Sign calculates the the signature or MAC for the given
	// byte slice and returns the signature bytes.
	Sign(data []byte) ([]byte, error)
}

// Verifier defines the interface for types verifying signatures.
type Verifier interface {
	// Verify is called to verify the given signature for the given data.
	// Implementations return nil in case of a valid signature or a non-nil error.
	// Implementation MUST NOT modify neither data nor signature.
	Verify(alg SignatureAlgorithm, data []byte, signature []byte) error
}

// SignerVerifier is the combination of both Signer and
// Verifier. It is used for symmetric signatures (i.e. MACs).
type SignerVerifier interface {
	Signer
	Verifier
}

type symmetricSignature struct {
	Signer
}

func (s *symmetricSignature) Verify(alg SignatureAlgorithm, data []byte, signature []byte) error {
	if alg != s.Alg() {
		return ErrInvalidSignature
	}

	sig, err := s.Sign(data)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidSignature, err)
	}

	if !bytes.Equal(sig, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// SymmetricSignature creates a SignerVerifier
func SymmetricSignature(s Signer) SignerVerifier {
	return &symmetricSignature{
		Signer: s,
	}
}

// --

const (
	ALG_NONE SignatureAlgorithm = "none"
)

// None returns a signature method that creates no signature.
// Use this method to create unsecured JWTs as specified in
// RFC7519 section 6 (https://datatracker.ietf.org/doc/html/rfc7519#section-6)
func None() SignerVerifier {
	return SymmetricSignature(&noneSignatureMethod{})
}

type noneSignatureMethod struct{}

func (m *noneSignatureMethod) Alg() SignatureAlgorithm {
	return ALG_NONE
}

func (m *noneSignatureMethod) Sign(data []byte) ([]byte, error) {
	return []byte{}, nil
}
