package tlv

import (
	"bytes"
	"reflect"
	"testing"
)

type test struct {
	Num     []uint64 `tlv:"255"`
	String  string   `tlv:"65535"`
	Byte    []byte   `tlv:"4294967295"`
	Bool    bool     `tlv:"18446744073709551615"`
	Special *special `tlv:"1"`
}

type special struct {
	i uint8
}

func (s *special) MarshalBinary() ([]byte, error) {
	return []byte{s.i}, nil
}

func (s *special) UnmarshalBinary(b []byte) error {
	if len(b) > 0 {
		s.i = b[0]
	}
	return nil
}

var (
	v1 = &test{
		Num:     []uint64{1<<8 - 1, 1<<16 - 1, 1<<32 - 1, 1<<64 - 1},
		String:  "string",
		Byte:    []byte{0x1, 0x2, 0x3},
		Bool:    true,
		Special: &special{i: 123},
	}
)

func TestTLV(t *testing.T) {
	buf := new(bytes.Buffer)
	err := Marshal(buf, v1, 1)
	if err != nil {
		t.Fatal(err)
	}
	v2 := &test{}
	err = Unmarshal(NewReader(buf), &v2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v1, v2) {
		t.Fatal("not equal", v1, v2)
	}
}
