// Package encoding defines function to encode and decode binary data
// in base64url format with no padding as specified in RFC 7515 section 2
// (https://datatracker.ietf.org/doc/html/rfc7515#section-2)
package encoding

import "encoding/base64"

var (
	enc = base64.URLEncoding.WithPadding(base64.NoPadding)
)

// Encode encodes the given data using base64URL encoding with no padding.
func Encode(data []byte) string {
	return enc.EncodeToString(data)
}

// Encode encodes the given base64URL encoded string.
func Decode(data string) ([]byte, error) {
	return enc.DecodeString(data)
}
