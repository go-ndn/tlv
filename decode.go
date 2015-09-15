package tlv

import "reflect"

func UnmarshalByte(b []byte, v interface{}, t uint64) error {
	_, err := readTLV(b, t, reflect.ValueOf(v))
	return err
}
