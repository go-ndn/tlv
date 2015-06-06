package tlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
)

var (
	ErrMissingType = errors.New("type not specified")
)

// Marshal writes arbitrary data to tlv.Writer
//
// Struct tag is "tlv", which specifies tlv type number.
//
// '?': do not write on zero value
//
// '*': signature
func Marshal(w Writer, i interface{}, valType uint64) error {
	return encode(w, reflect.ValueOf(i), valType, false, false)
}

func MarshalByte(i interface{}, valType uint64) (b []byte, err error) {
	buf := new(bytes.Buffer)
	err = Marshal(buf, i, valType)
	if err != nil {
		return
	}
	b = buf.Bytes()
	return
}

// Data writes all internal tlv bytes except * marked fields
func Data(w Writer, i interface{}) error {
	value := reflect.Indirect(reflect.ValueOf(i))
	if value.Kind() != reflect.Struct {
		return ErrNotSupported
	}
	return encodeStruct(w, value, true)
}

func WriteVarNum(w io.Writer, v uint64) (err error) {
	b := make([]byte, 9)
	switch {
	case v > math.MaxUint32:
		b[0] = 0xFF
		binary.BigEndian.PutUint64(b[1:], v)
		_, err = w.Write(b)
	case v > math.MaxUint16:
		b[0] = 0xFE
		binary.BigEndian.PutUint32(b[1:], uint32(v))
		_, err = w.Write(b[:5])
	case v > math.MaxUint8-3:
		b[0] = 0xFD
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		_, err = w.Write(b[:3])
	default:
		b[0] = uint8(v)
		_, err = w.Write(b[:1])
	}
	return
}

func encodeUint64(w io.Writer, v uint64) (err error) {
	b := make([]byte, 9)
	switch {
	case v > math.MaxUint32:
		b[0] = 8
		binary.BigEndian.PutUint64(b[1:], v)
		_, err = w.Write(b)
	case v > math.MaxUint16:
		b[0] = 4
		binary.BigEndian.PutUint32(b[1:], uint32(v))
		_, err = w.Write(b[:5])
	case v > math.MaxUint8:
		b[0] = 2
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		_, err = w.Write(b[:3])
	default:
		b[0] = 1
		b[1] = uint8(v)
		_, err = w.Write(b[:2])
	}
	return
}

type structTag struct {
	Type     uint64
	Optional bool
	NotData  bool
	Extended bool
}

func parseTag(t reflect.StructTag) (tag *structTag, err error) {
	s := t.Get("tlv")
	if s == "" {
		err = ErrMissingType
		return
	}
	valType, err := strconv.ParseUint(strings.TrimRight(s, "?*+"), 10, 64)
	if err != nil {
		return
	}
	tag = &structTag{
		Optional: strings.Contains(s, "?"),
		NotData:  strings.Contains(s, "*"),
		Extended: strings.Contains(s, "+"),
		Type:     valType,
	}
	return
}

func encode(w Writer, value reflect.Value, valType uint64, dataOnly, extended bool) (err error) {
	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			err = WriteVarNum(w, valType)
			if err != nil {
				return
			}
			_, err = w.Write([]byte{0})
			if err != nil {
				return
			}
		}
	case reflect.Uint64:
		err = WriteVarNum(w, valType)
		if err != nil {
			return
		}
		err = encodeUint64(w, value.Uint())
		if err != nil {
			return
		}
	case reflect.Slice:
		switch value.Type().Elem().Kind() {
		case reflect.Uint8:
			err = WriteVarNum(w, valType)
			if err != nil {
				return
			}
			b := value.Bytes()
			err = WriteVarNum(w, uint64(len(b)))
			if err != nil {
				return
			}
			_, err = w.Write(b)
			if err != nil {
				return
			}
		case reflect.Struct:
			if extended {
				buf := new(bytes.Buffer)
				for j := 0; j < value.Len(); j++ {
					err = encodeStruct(buf, value.Index(j), dataOnly)
					if err != nil {
						return
					}
				}
				err = WriteVarNum(w, valType)
				if err != nil {
					return
				}
				err = WriteVarNum(w, uint64(buf.Len()))
				if err != nil {
					return
				}
				_, err = buf.WriteTo(w)
				return
			}
			fallthrough
		default:
			for j := 0; j < value.Len(); j++ {
				err = encode(w, value.Index(j), valType, dataOnly, false)
				if err != nil {
					return
				}
			}
		}
	case reflect.String:
		err = WriteVarNum(w, valType)
		if err != nil {
			return
		}
		s := value.String()
		err = WriteVarNum(w, uint64(len(s)))
		if err != nil {
			return
		}
		_, err = w.Write([]byte(s))
		if err != nil {
			return
		}
	case reflect.Ptr:
		err = encode(w, value.Elem(), valType, dataOnly, false)
		if err != nil {
			return
		}
	case reflect.Struct:
		buf := new(bytes.Buffer)
		err = encodeStruct(buf, value, dataOnly)
		if err != nil {
			return
		}
		err = WriteVarNum(w, valType)
		if err != nil {
			return
		}
		err = WriteVarNum(w, uint64(buf.Len()))
		if err != nil {
			return
		}
		_, err = buf.WriteTo(w)
		if err != nil {
			return
		}
	default:
		err = ErrNotSupported
		return
	}
	return
}

func walkStruct(structType reflect.Type, f func(*structTag, int) error) (err error) {
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if field.PkgPath != "" {
			// unexported
			continue
		}
		var tag *structTag
		tag, err = parseTag(field.Tag)
		if err != nil {
			return
		}
		if tag.Extended && (field.Type.Kind() != reflect.Slice || field.Type.Elem().Kind() != reflect.Struct) {
			err = ErrNotSupported
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

func encodeStruct(w Writer, structValue reflect.Value, dataOnly bool) error {
	return walkStruct(structValue.Type(), func(tag *structTag, i int) error {
		fieldValue := structValue.Field(i)
		if tag.NotData && dataOnly ||
			tag.Optional && isZero(fieldValue) {
			return nil
		}
		return encode(w, fieldValue, tag.Type, dataOnly, tag.Extended)
	})
}
