package tlv

import (
	"hash"
	"reflect"
)

// Marshal returns the tlv encoding of v.
//
// The "tlv" struct tag specifies tlv type number.
// '?' after type number indicates that this tlv
// should be omitted if the value is empty.
func Marshal(v interface{}, t uint64) ([]byte, error) {
	b := make([]byte, MaxSize)
	n, err := writeTLV(b, t, reflect.ValueOf(v), false)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

// Hash returns the digest of tlv-encoded data.
//
// See Marshal.
//
// '*' after type number indicates this tlv
// is signature, and should be omitted in digest calculation.
func Hash(f func() hash.Hash, v interface{}) ([]byte, error) {
	value := reflect.Indirect(reflect.ValueOf(v))
	if value.Kind() != reflect.Struct {
		return nil, ErrNotSupported
	}
	b := make([]byte, MaxSize)
	n, err := writeStruct(b, value, true)
	if err != nil {
		return nil, err
	}
	h := f()
	h.Write(b[:n])
	return h.Sum(nil), nil
}
