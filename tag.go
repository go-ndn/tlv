package tlv

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
)

// Errors introduced by parsing struct tags.
var (
	ErrMissingType  = errors.New("type not specified")
	errNotZeroValue = errors.New("value not zero")
)

type structTag struct {
	Type      uint64
	Optional  bool
	Signature bool
}

// TODO: strings.TrimRight allocates due to strings.makeCutsetFunc
func isOption(r rune) bool {
	return strings.IndexRune("?*", r) >= 0
}

func (tag *structTag) parse(t reflect.StructTag) (err error) {
	s := t.Get("tlv")
	if s == "" {
		err = ErrMissingType
		return
	}
	tag.Optional = strings.Contains(s, "?")
	tag.Signature = strings.Contains(s, "*")
	tag.Type, err = strconv.ParseUint(strings.TrimRightFunc(s, isOption), 10, 64)
	return
}

// parseStruct parses tag of every struct field.
//
// An unexported field is represented by nil instead.
func parseStruct(structType reflect.Type) (tags []*structTag, err error) {
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if field.PkgPath != "" && !field.Anonymous {
			// unexported
			tags = append(tags, nil)
			continue
		}
		tag := new(structTag)
		err = tag.parse(field.Tag)
		if err != nil {
			return
		}
		tags = append(tags, tag)
	}
	return
}

var (
	cache = make(map[reflect.Type][]*structTag)
)

// CacheType caches struct tags to prevent allocation on common types.
func CacheType(v interface{}) error {
	return cacheType(reflect.TypeOf(v))
}

func cacheType(t reflect.Type) (err error) {
	if _, ok := cache[t]; ok {
		return
	}
	switch t.Kind() {
	case reflect.Ptr:
		err = cacheType(t.Elem())
		if err != nil {
			return
		}
	case reflect.Struct:
		var tags []*structTag
		tags, err = parseStruct(t)
		if err != nil {
			return
		}
		cache[t] = tags
		for i, tag := range tags {
			if tag == nil {
				continue
			}
			err = cacheType(t.Field(i).Type)
			if err != nil {
				return
			}
		}
	}
	return
}

// walkStruct parses tag of every struct field, and invokes f if the field is exported.
func walkStruct(structType reflect.Type, f func(*structTag, int) error) (err error) {
	tags, ok := cache[structType]
	if !ok {
		tags, err = parseStruct(structType)
		if err != nil {
			return
		}
	}
	for i, tag := range tags {
		if tag == nil {
			continue
		}
		err = f(tag, i)
		if err != nil {
			return
		}
	}
	return
}

// isZero checks whether reflect.Value is empty.
//
// TODO: reflect.Zero allocates
func isZero(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Bool:
		return !value.Bool()
	case reflect.Uint64:
		return value.Uint() == 0
	case reflect.Slice:
		fallthrough
	case reflect.String:
		return value.Len() == 0
	case reflect.Ptr:
		return value.IsNil() || isZero(value.Elem())
	case reflect.Struct:
		return nil == walkStruct(value.Type(), func(_ *structTag, i int) error {
			if isZero(value.Field(i)) {
				return nil
			}
			return errNotZeroValue
		})
	default:
		return false
	}
}
