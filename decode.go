package tlv

import "reflect"

func Unmarshal(b []byte, v interface{}, t uint64) error {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Ptr || value.IsNil() {
		return ErrInvalidPtr
	}
	_, err := readTLV(b, t, value.Elem())
	return err
}
