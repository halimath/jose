package jws_test

import (
	"fmt"

	"github.com/halimath/jwx/jws"
)

func Example() {
	signatureMethod := jws.HS256([]byte("secret"))

	sig, err := jws.Sign(signatureMethod, []byte("hello, world"), jws.Header{})
	if err != nil {
		panic(err)
	}

	compact := sig.Compact()

	fmt.Println(compact)

	sig2, err := jws.ParseCompact(compact)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(sig2.Payload()))

	// Output:
	// eyJhbGciOiJIUzI1NiJ9.aGVsbG8sIHdvcmxk.4BeqMvZFJ1IIIpDSQhXK05lFaJ5k9G39y7CNs8xdfjI
	// hello, world
}
