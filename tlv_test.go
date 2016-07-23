package tlv

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"
)

type testStruct struct {
	Ptr        *struct{} `tlv:"1"`
	Time       time.Time `tlv:"2"`
	String     string    `tlv:"252"`
	Num        []uint64  `tlv:"65535"`
	Byte       []byte    `tlv:"4294967295"`
	Bool       bool      `tlv:"18446744073709551615"`
	unexported uint8
}

func (t *testStruct) ReadFrom(r Reader) error {
	return r.Read(t, 1)
}

func (t testStruct) WriteTo(w Writer) error {
	return w.Write(t, 1)
}

var (
	ref = &testStruct{
		Ptr:    new(struct{}),
		Time:   time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		String: "one",
		Num:    []uint64{1<<8 - 1, 1<<16 - 1, 1<<32 - 1, 1<<64 - 1},
		Byte:   []byte{0x1, 0x2, 0x3},
		Bool:   true,
	}
	refBool bool
)

func TestMarshal(t *testing.T) {
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
			from: &refBool,
			to:   new(bool),
		},
		{
			from: &ref.Bool,
			to:   new(bool),
		},
		{
			from: &[]uint64{},
			to:   &[]uint64{},
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
		b, err := Marshal(test.from, 1)
		if err != nil {
			t.Fatal(err)
		}
		err = Unmarshal(b, test.to, 1)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(test.from, test.to) {
			t.Fatalf("expect %+v, got %+v", test.from, test.to)
		}
	}
}

func TestReaderPeek(t *testing.T) {
	for _, test := range []struct {
		in   []byte
		want uint64
	}{
		{
			in:   []byte{1, 0},
			want: 1,
		},
		{
			in:   []byte{253, 255, 255, 0},
			want: 65535,
		},
		{
			in:   []byte{254, 255, 255, 255, 255, 0},
			want: 4294967295,
		},
		{
			in:   []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 0},
			want: 18446744073709551615,
		},
		{
			want: 0,
		},
	} {
		got := NewReader(bytes.NewReader(test.in)).Peek()
		if test.want != got {
			t.Fatalf("Peek() == %d, got %d", test.want, got)
		}
	}
}

func TestReadWriter(t *testing.T) {
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

func TestCopyDiffType(t *testing.T) {
	v := new(testStruct)
	err := Copy(v, *ref)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ref, v) {
		t.Fatalf("expect %+v, got %+v", ref, v)
	}
}

func TestCopySameType(t *testing.T) {
	v := new(testStruct)
	err := Copy(v, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ref, v) {
		t.Fatalf("expect %+v, got %+v", ref, v)
	}
}

func TestHash(t *testing.T) {
	var want = []byte{
		0xab, 0xed, 0x36, 0x46, 0x42, 0x6d, 0xfd, 0x9a,
		0xf8, 0x73, 0x3a, 0x4, 0xd0, 0x3e, 0x53, 0x95,
		0x95, 0x14, 0xb4, 0xc2, 0x8b, 0x6, 0xc3, 0x77,
		0xc7, 0xf5, 0x4c, 0xfb, 0x2d, 0x69, 0x58, 0xc8,
	}
	got, err := Hash(sha256.New, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("expect %v, got %v", want, got)
	}
}
