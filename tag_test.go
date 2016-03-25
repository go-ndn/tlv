package tlv

import (
	"reflect"
	"testing"
)

func TestCacheType(t *testing.T) {
	err := CacheType((*testStruct)(nil))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []reflect.Type{
		reflect.TypeOf(ref.Time),
		reflect.TypeOf(*ref),
	} {
		if _, ok := cache[test]; !ok {
			t.Fatalf("expect %v", test)
		}
	}
}

func TestIsZero(t *testing.T) {
	for _, test := range []struct {
		in   interface{}
		want bool
	}{
		{
			in:   "",
			want: true,
		},
		{
			in:   (*struct{})(nil),
			want: true,
		},
		{
			in:   uint64(0),
			want: true,
		},
		{
			in:   false,
			want: true,
		},
		{
			in:   ([]struct{})(nil),
			want: true,
		},
		{
			in:   struct{}{},
			want: true,
		},
		{
			in:   nil,
			want: false,
		},
	} {
		got := isZero(reflect.ValueOf(test.in))
		if test.want != got {
			t.Fatalf("isZero(%v) == %v, got %v", test.in, test.want, got)
		}
	}
}
