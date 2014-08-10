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
		String     string      `tlv:"2?"`
		Bytes      []byte      `tlv:"3"`
		Containers []Container `tlv:"5"`
		Ptrs       []*uint64   `tlv:"7"`
	}
	v1 := Test{
		Num:    123,
		String: "",
		Bytes:  []byte{0x1, 0x2, 0x3},
		Containers: []Container{
			{V: 100},
			{V: 200},
		},
		Ptrs: []*uint64{
			new(uint64),
			new(uint64),
		},
	}
	b := new(bytes.Buffer)
	err := Marshal(b, v1, 9)
	if err != nil {
		t.Error(err)
	}
	spew.Dump(b.Bytes())
	saved := b.Bytes()
	v2 := Test{}
	err = Unmarshal(b, &v2, 9)
	if err != nil {
		t.Error(err)
	}
	spew.Dump(v2)
	b2 := new(bytes.Buffer)
	err = Marshal(b2, v2, 9)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(saved, b2.Bytes()) {
		t.Error("not equal", saved, b2.Bytes())
	}
}
