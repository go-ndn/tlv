package tlv

import (
	"bytes"
	"encoding"
	"reflect"
)

// Copy copies from src to dst.
// If src and dst have the same type, it will perform direct copying with reflection.
// Otherwise copying will happen with tlv representation.
func Copy(dst ReadFrom, src WriteTo) (err error) {
	dstValue, srcValue := reflect.ValueOf(dst), reflect.ValueOf(src)
	if dstValue.Kind() == reflect.Ptr && !dstValue.IsNil() &&
		dstValue.Type() == srcValue.Type() {
		return cpy(dstValue.Elem(), srcValue.Elem())
	}
	buf := new(bytes.Buffer)
	err = src.WriteTo(NewWriter(buf))
	if err != nil {
		return
	}
	err = dst.ReadFrom(NewReader(buf))
	return
}

func cpy(dst, src reflect.Value) (err error) {
	if src.Type().Implements(typeBinaryMarshaler) && dst.Addr().Type().Implements(typeBinaryUnmarshaler) {
		var v []byte
		v, err = src.Interface().(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			return
		}
		err = dst.Addr().Interface().(encoding.BinaryUnmarshaler).UnmarshalBinary(v)
		return
	}
	switch dst.Kind() {
	case reflect.Slice:
		if src.IsNil() {
			return
		}
		switch dst.Type().Elem().Kind() {
		case reflect.Uint8:
			srcb := src.Bytes()
			dstb := make([]byte, len(srcb))
			copy(dstb, srcb)
			dst.SetBytes(dstb)
		default:
			dst.Set(reflect.MakeSlice(dst.Type(), src.Len(), src.Len()))
			for i := 0; i < dst.Len(); i++ {
				err = cpy(dst.Index(i), src.Index(i))
				if err != nil {
					return
				}
			}
		}
	case reflect.Ptr:
		if src.IsNil() {
			return
		}
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		err = cpy(dst.Elem(), src.Elem())
	case reflect.Struct:
		return walkStruct(dst.Type(), func(_ *structTag, i int) error {
			return cpy(dst.Field(i), src.Field(i))
		})
	case reflect.String:
		fallthrough
	case reflect.Bool:
		fallthrough
	case reflect.Uint64:
		dst.Set(src)
	default:
		err = ErrNotSupported
	}
	return
}
