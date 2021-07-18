package encoding

import "testing"

func TestEncode(t *testing.T) {
	act := Encode([]byte("hello, world"))

	if act != "aGVsbG8sIHdvcmxk" {
		t.Errorf("unexpected encoded string: '%s'", act)
	}
}

func TestDecode(t *testing.T) {
	act, err := Decode("aGVsbG8sIHdvcmxk")
	if err != nil {
		t.Fatal(err)
	}

	if string(act) != "hello, world" {
		t.Errorf("unexpected decoded string: '%s'", string(act))
	}
}
