package tlv

import (
	"bytes"
	"encoding"
	"reflect"
)

// Copy copies from src to dst.
// If src and dst have the same type, it will perform direct copying with reflection.
// Otherwise copying will happen with tlv representation.
func Copy(dst ReadFrom, src WriteTo) error {
	dstValue, srcValue := reflect.ValueOf(dst), reflect.ValueOf(src)
	if dstValue.Kind() == reflect.Ptr && !dstValue.IsNil() &&
		dstValue.Type() == srcValue.Type() {
		return cpy(dstValue.Elem(), srcValue.Elem())
	}
	buf := new(bytes.Buffer)
	err := src.WriteTo(NewWriter(buf))
	if err != nil {
		return err
	}
	return dst.ReadFrom(NewReader(buf))
}

func cpy(dst, src reflect.Value) error {
	if src.Type().Implements(typeBinaryMarshaler) && dst.Addr().Type().Implements(typeBinaryUnmarshaler) {
		v, err := src.Interface().(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			return err
		}
		return dst.Addr().Interface().(encoding.BinaryUnmarshaler).UnmarshalBinary(v)
	}
	switch dst.Kind() {
	case reflect.Slice:
		if src.IsNil() {
			return nil
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
				err := cpy(dst.Index(i), src.Index(i))
				if err != nil {
					return err
				}
			}
		}
	case reflect.Ptr:
		if src.IsNil() {
			return nil
		}
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		return cpy(dst.Elem(), src.Elem())
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
		return ErrNotSupported
	}
	return nil
}
