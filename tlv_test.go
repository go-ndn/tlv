package tlv

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"
)

type testStruct struct {
	String     string   `tlv:"252"`
	Num        []uint64 `tlv:"65535"`
	Byte       []byte   `tlv:"4294967295"`
	Bool       bool     `tlv:"18446744073709551615"`
	unexported uint8
}

func (t *testStruct) ReadFrom(r Reader) error {
	return r.Read(t, 1)
}

func (t *testStruct) WriteTo(w Writer) error {
	return w.Write(t, 1)
}

var (
	ref = &testStruct{
		String: "one",
		Num:    []uint64{1<<8 - 1, 1<<16 - 1, 1<<32 - 1, 1<<64 - 1},
		Byte:   []byte{0x1, 0x2, 0x3},
		Bool:   true,
	}
)

func TestTLV(t *testing.T) {
	v1 := new(testStruct)
	b, err := MarshalByte(ref, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = UnmarshalByte(b, v1, 1)
	if err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	err = ref.WriteTo(NewWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	v2 := new(testStruct)
	err = v2.ReadFrom(NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}

	v3 := new(testStruct)
	err = Copy(v3, ref)
	if err != nil {
		t.Fatal(err)
	}

	want, err := Hash(sha256.New, ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []*testStruct{v1, v2, v3} {
		if !reflect.DeepEqual(ref, v) {
			t.Fatalf("expect %+v, got %+v", ref, v)
		}

		got, err := Hash(sha256.New, v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("expect %v, got %v", want, got)
		}
	}
}
