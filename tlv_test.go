package tlv

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"
)

type testStruct struct {
	Time       time.Time `tlv:"1"`
	String     string    `tlv:"252"`
	Num        []uint64  `tlv:"65535"`
	Byte       []byte    `tlv:"4294967295"`
	Bool       bool      `tlv:"18446744073709551615"`
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
		Time:   time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		String: "one",
		Num:    []uint64{1<<8 - 1, 1<<16 - 1, 1<<32 - 1, 1<<64 - 1},
		Byte:   []byte{0x1, 0x2, 0x3},
		Bool:   true,
	}
)

func TestMarshal(t *testing.T) {
	CacheType(reflect.TypeOf((*testStruct)(nil)))

	for _, test := range []struct {
		to   interface{}
		from interface{}
	}{
		{
			from: &ref.Time,
			to:   new(time.Time),
		},
		{
			from: &ref.String,
			to:   new(string),
		},
		{
			from: &ref.Bool,
			to:   new(bool),
		},
		{
			from: &ref.Num,
			to:   &[]uint64{},
		},
		{
			from: &ref.Byte,
			to:   &[]byte{},
		},
		{
			from: ref,
			to:   new(testStruct),
		},
	} {
		b, err := MarshalByte(test.from, 1)
		if err != nil {
			t.Fatal(err)
		}
		err = UnmarshalByte(b, test.to, 1)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(test.from, test.to) {
			t.Fatalf("expect %+v, got %+v", test.from, test.to)
		}
	}
}

func TestReadWriter(t *testing.T) {
	CacheType(reflect.TypeOf((*testStruct)(nil)))

	for _, test := range []struct {
		to   interface{}
		from interface{}
	}{
		{
			from: &ref.String,
			to:   new(string),
		},
		{
			from: &ref.Bool,
			to:   new(bool),
		},
		// ignore []uint64 because reader can only read in one tlv
		{
			from: &ref.Byte,
			to:   &[]byte{},
		},
		{
			from: ref,
			to:   new(testStruct),
		},
	} {
		buf := new(bytes.Buffer)
		err := NewWriter(buf).Write(test.from, 1)
		if err != nil {
			t.Fatal(err)
		}
		err = NewReader(buf).Read(test.to, 1)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(test.from, test.to) {
			t.Fatalf("expect %+v, got %+v", test.from, test.to)
		}
	}
}

func TestCopyHash(t *testing.T) {
	v := new(testStruct)
	err := Copy(v, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ref, v) {
		t.Fatalf("expect %+v, got %+v", ref, v)
	}

	want, err := Hash(sha256.New, ref)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Hash(sha256.New, v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("expect %v, got %v", want, got)
	}
}
