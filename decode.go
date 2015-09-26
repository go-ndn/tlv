package tlv

import "reflect"

func UnmarshalByte(b []byte, v interface{}, t uint64) error {
	// redirect is required for ptr to slice
	_, err := readTLV(b, t, reflect.Indirect(reflect.ValueOf(v)))
	return err
}
