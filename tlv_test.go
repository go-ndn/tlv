package tlv

import (
	"reflect"
	"testing"
)

type extended []struct {
	String1 string `tlv:"1"`
	String2 string `tlv:"2"`
}

type test struct {
	Extended   extended `tlv:"252+"`
	Num        []uint64 `tlv:"65535"`
	Byte       []byte   `tlv:"4294967295"`
	Bool       bool     `tlv:"18446744073709551615"`
	unexported uint8
}

func (t *test) ReadFrom(r Reader) error {
	return Unmarshal(r, t, 1)
}

func (t *test) WriteTo(w Writer) error {
	return Marshal(w, t, 1)
}

func TestTLV(t *testing.T) {
	v1 := &test{
		Extended: extended{
			{"one", "1"},
			{"two", "2"},
			{"three", "3"},
			{"four", "4"},
		},
		Num:  []uint64{1<<8 - 1, 1<<16 - 1, 1<<32 - 1, 1<<64 - 1},
		Byte: []byte{0x1, 0x2, 0x3},
		Bool: true,
	}

	v2 := new(test)
	b, err := MarshalByte(v1, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = UnmarshalByte(b, v2, 1)
	if err != nil {
		t.Fatal(err)
	}

	v3 := new(test)
	err = Copy(v1, v3)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range []*test{v2, v3} {
		if !reflect.DeepEqual(v1, v) {
			t.Fatal("not equal", v1, v)
		}
	}
}
