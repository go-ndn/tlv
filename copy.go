package tlv

import (
	"bytes"
	"reflect"
)

func Copy(dst ReadFrom, src WriteTo) (err error) {
	if reflect.TypeOf(dst) == reflect.TypeOf(src) {
		return cpy(reflect.ValueOf(dst), reflect.ValueOf(src))
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
	switch dst.Kind() {
	case reflect.Bool:
		dst.SetBool(src.Bool())
	case reflect.Uint64:
		dst.SetUint(src.Uint())
	case reflect.Slice:
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
	case reflect.String:
		dst.SetString(src.String())
	case reflect.Ptr:
		if dst.CanSet() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		err = cpy(dst.Elem(), src.Elem())
	case reflect.Struct:
		return walkStruct(dst.Type(), func(_ *structTag, i int) error {
			return cpy(dst.Field(i), src.Field(i))
		})
	default:
		err = ErrNotSupported
	}
	return
}
