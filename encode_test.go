package tlv

import (
	"bytes"
	"github.com/davecgh/go-spew/spew"
	"testing"
)

func TestEncoding(t *testing.T) {
	type Container struct {
		V uint64 `tlv:"6"`
	}
	type Test struct {
		Num        uint64      `tlv:"1"`
		String     string      `tlv:"2,-"`
		Bytes      []byte      `tlv:"3"`
		Containers []Container `tlv:"5"`
	}
	v1 := Test{
		Num:    123,
		String: "hello",
		Bytes:  []byte{0x1, 0x2, 0x3},
		Containers: []Container{
			{V: 100},
			{V: 200},
		},
	}
	b, err := Marshal(v1, 9)
	if err != nil {
		t.Error(err)
	}
	spew.Dump(b)
	v2 := Test{}
	err = Unmarshal(b, &v2, 9)
	if err != nil {
		t.Error(err)
	}
	spew.Dump(v2)
	b2, err := Marshal(v2, 9)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(b, b2) {
		t.Error("not equal", b, b2)
	}
}
