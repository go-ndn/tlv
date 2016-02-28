package tlv

import "reflect"

// Unmarshal parses the tlv-encoded data
// and stores the result in the value pointed to by v.
func Unmarshal(b []byte, v interface{}, t uint64) error {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Ptr || value.IsNil() {
		return ErrInvalidPtr
	}
	_, err := readTLV(b, t, value.Elem())
	return err
}
