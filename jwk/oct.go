package jwk

import (
	"encoding/json"
	"fmt"

	"github.com/halimath/jose/internal/encoding"
)

// SymmetricKey implements a symmertric secret of "kty": "oct" according to
// RFC 7517, section A.3.
// (https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.3)
type SymmetricKey struct {
	KeyDescription
	Bytes []byte
}

func (s *SymmetricKey) Type() KeyType {
	return KeyTypeOct
}

type symmetricKeyJSONWrapper struct {
	KeyDescription
	Type KeyType `json:"kty"`
	K    string  `json:"k"`
}

func (s *SymmetricKey) MarshalJSON() ([]byte, error) {
	w := symmetricKeyJSONWrapper{
		KeyDescription: s.KeyDescription,
		Type:           s.Type(),
		K:              encoding.Encode(s.Bytes),
	}

	return json.Marshal(w)
}

func (s *SymmetricKey) UnmarshalJSON(data []byte) error {
	var w symmetricKeyJSONWrapper

	err := json.Unmarshal(data, &w)
	if err != nil {
		return err
	}

	s.KeyDescription = w.KeyDescription
	s.Bytes, err = encoding.Decode(w.K)
	if err != nil {
		return fmt.Errorf("failed to decode oct key bytes: %v", err)
	}

	return nil
}
