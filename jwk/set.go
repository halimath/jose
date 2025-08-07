package jwk

import (
	"encoding/json"
)

// KeyFilter defines a function type to use to filter Keys in a Set.
type KeyFilter func(k Key) bool

// WithID create a KeyFilter that filters Keys by ID.
func WithID(kid string) KeyFilter {
	return func(k Key) bool {
		return k.ID() == kid
	}
}

// Set implements a set of keys.
type Set []Key

// Has checks whether s contains at least one Key matching f.
func (s Set) Has(f KeyFilter) bool {
	for _, k := range s {
		if f(k) {
			return true
		}
	}
	return false
}

// First returns the first key in s which matches f or
// nil, if no key matches f.
func (s Set) First(f KeyFilter) Key {
	for _, k := range s {
		if f(k) {
			return k
		}
	}
	return nil
}

const (
	ParamKey = "keys"
)

func (s Set) MarshalJSON() ([]byte, error) {
	type wrapper struct {
		Keys []Key `json:"keys"`
	}

	w := wrapper{Keys: s}

	return json.Marshal(w)
}

func (s *Set) UnmarshalJSON(data []byte) error {
	type setWrapper struct {
		Keys []json.RawMessage `json:"keys"`
	}

	var w setWrapper
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}

	*s = make(Set, len(w.Keys))
	var err error

	for i, rm := range w.Keys {
		(*s)[i], err = UnmarshalKey(rm)
		if err != nil {
			return err
		}
	}

	return nil
}
