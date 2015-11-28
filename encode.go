package tlv

import (
	"hash"
	"reflect"
)

// Marshal writes arbitrary data to tlv.Writer
//
// Struct tag is "tlv", which specifies tlv type number.
//
// '?': do not write on zero value
//
// '*': signature
func Marshal(v interface{}, t uint64) (b []byte, err error) {
	b = make([]byte, maxSize)
	n, err := writeTLV(b, t, reflect.ValueOf(v), false)
	if err != nil {
		return
	}
	b = b[:n]
	return
}

func Hash(f func() hash.Hash, v interface{}) (digest []byte, err error) {
	value := reflect.Indirect(reflect.ValueOf(v))
	if value.Kind() != reflect.Struct {
		err = ErrNotSupported
		return
	}
	b := make([]byte, maxSize)
	n, err := writeStruct(b, value, true)
	if err != nil {
		return
	}
	h := f()
	h.Write(b[:n])
	digest = h.Sum(nil)
	return
}
