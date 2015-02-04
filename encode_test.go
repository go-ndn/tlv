package tlv

import (
	"bytes"
	"reflect"
	"testing"
)

type Container struct {
	V uint64 `tlv:"6"`
}
type Test struct {
	Num        uint64      `tlv:"1"`
	String     string      `tlv:"2?"`
	Bytes      []byte      `tlv:"3"`
	Containers []Container `tlv:"5"`
}

var (
	v1 = Test{
		Num:    123,
		String: "124",
		Bytes:  []byte{0x1, 0x2, 0x3},
		Containers: []Container{
			{V: 100},
			{V: 200},
		},
	}
)

func TestTLV(t *testing.T) {
	buf := new(bytes.Buffer)
	err := Marshal(buf, v1, 6)
	if err != nil {
		t.Fatal(err)
	}
	v2 := Test{}
	err = Unmarshal(NewReader(buf), &v2, 6)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v1, v2) {
		t.Fatal("not equal", v1, v2)
	}
}
