package tlv

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
)

var (
	ErrMissingType = errors.New("type not specified")
)

type structTag struct {
	Type      uint64
	Optional  bool
	Signature bool
}

func (tag *structTag) parse(t reflect.StructTag) (err error) {
	s := t.Get("tlv")
	if s == "" {
		err = ErrMissingType
		return
	}
	tag.Optional = strings.Contains(s, "?")
	tag.Signature = strings.Contains(s, "*")
	tag.Type, err = strconv.ParseUint(strings.TrimRight(s, "?*"), 10, 64)
	return
}

func walkStruct(structType reflect.Type, f func(*structTag, int) error) (err error) {
	tag := new(structTag)
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if field.PkgPath != "" {
			// unexported
			continue
		}
		err = tag.parse(field.Tag)
		if err != nil {
			return
		}
		err = f(tag, i)
		if err != nil {
			return
		}
	}
	return
}

func isZero(value reflect.Value) bool {
	return reflect.DeepEqual(value.Interface(), reflect.Zero(value.Type()).Interface())
}
