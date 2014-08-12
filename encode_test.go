package tlv

import (
	"bufio"
	"bytes"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
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
	buf := new(bytes.Buffer)
	err := Marshal(buf, v1, 9)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ioutil.ReadAll(buf)
	spew.Dump(b)
	v2 := Test{}
	err = Unmarshal(bufio.NewReader(bytes.NewBuffer(b)), &v2, 9)
	if err != nil {
		t.Fatal(err)
	}
	spew.Dump(v1)
	spew.Dump(v2)
	buf2 := new(bytes.Buffer)
	err = Marshal(buf2, v2, 9)
	if err != nil {
		t.Fatal(err)
	}

	b2, _ := ioutil.ReadAll(buf2)
	if !bytes.Equal(b, b2) {
		t.Fatal("not equal", b, b2)
	}
}
