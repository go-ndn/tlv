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
func Marshal(v interface{}, t uint64) (b []byte, err error) {
	b = make([]byte, MaxSize)
	n, err := writeTLV(b, t, reflect.ValueOf(v), false)
	if err != nil {
		return
	}
	b = b[:n]
	return
}

// Hash returns the digest of tlv-encoded data.
//
// See Marshal.
//
// '*' after type number indicates this tlv
// is signature, and should be omitted in digest calculation.
func Hash(f func() hash.Hash, v interface{}) (digest []byte, err error) {
	value := reflect.Indirect(reflect.ValueOf(v))
	if value.Kind() != reflect.Struct {
		err = ErrNotSupported
		return
	}
	b := make([]byte, MaxSize)
	n, err := writeStruct(b, value, true)
	if err != nil {
		return
	}
	h := f()
	h.Write(b[:n])
	digest = h.Sum(nil)
	return
}
