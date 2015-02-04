package tlv

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
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
//
// '-': implicit (never write)
func Marshal(buf Writer, i interface{}, valType uint64) error {
	return encode(buf, reflect.ValueOf(i), valType, false)
}

// Data writes all internal tlv bytes except * marked fields
func Data(buf Writer, i interface{}) error {
	value := reflect.Indirect(reflect.ValueOf(i))
	if value.Kind() != reflect.Struct {
		return ErrNotSupported
	}
	return encodeStruct(buf, value, true)
}

func writeVarNum(buf Writer, v uint64) (err error) {
	b := make([]byte, 9)
	switch {
	case v > math.MaxUint32:
		b[0] = 0xFF
		binary.BigEndian.PutUint64(b[1:], v)
		_, err = buf.Write(b)
	case v > math.MaxUint16:
		b[0] = 0xFE
		binary.BigEndian.PutUint32(b[1:], uint32(v))
		_, err = buf.Write(b[:5])
	case v > math.MaxUint8-3:
		b[0] = 0xFD
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		_, err = buf.Write(b[:3])
	default:
		b[0] = uint8(v)
		_, err = buf.Write(b[:1])
	}
	return
}

func encodeUint64(buf Writer, v uint64) (err error) {
	b := make([]byte, 9)
	switch {
	case v > math.MaxUint32:
		b[0] = 8
		binary.BigEndian.PutUint64(b[1:], v)
		_, err = buf.Write(b)
	case v > math.MaxUint16:
		b[0] = 4
		binary.BigEndian.PutUint32(b[1:], uint32(v))
		_, err = buf.Write(b[:5])
	case v > math.MaxUint8:
		b[0] = 2
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		_, err = buf.Write(b[:3])
	default:
		b[0] = 1
		b[1] = uint8(v)
		_, err = buf.Write(b[:2])
	}
	return
}

type structTag struct {
	Type     uint64
	Optional bool
	NotData  bool
	Implicit bool
}

func parseTag(t reflect.StructTag) (tag *structTag, err error) {
	s := t.Get("tlv")
	if s == "" {
		err = ErrMissingType
		return
	}
	tag = new(structTag)
	tag.Optional = strings.Contains(s, "?")
	tag.NotData = strings.Contains(s, "*")
	tag.Implicit = strings.Contains(s, "-")
	tag.Type, err = strconv.ParseUint(strings.TrimRight(s, "?*-"), 10, 64)
	return
}

func encode(buf Writer, value reflect.Value, valType uint64, dataOnly bool) (err error) {
	if w, ok := value.Interface().(encoding.BinaryMarshaler); ok {
		var data []byte
		data, err = w.MarshalBinary()
		if err != nil {
			return
		}
		writeVarNum(buf, valType)
		writeVarNum(buf, uint64(len(data)))
		_, err = buf.Write(data)
		return
	}
	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			writeVarNum(buf, valType)
			buf.Write([]byte{0})
		}
	case reflect.Uint64:
		writeVarNum(buf, valType)
		err = encodeUint64(buf, value.Uint())
		if err != nil {
			return
		}
	case reflect.Slice:
		switch value.Type().Elem().Kind() {
		case reflect.Uint8:
			writeVarNum(buf, valType)
			b := value.Bytes()
			writeVarNum(buf, uint64(len(b)))
			_, err = buf.Write(b)
			if err != nil {
				return
			}
		default:
			for j := 0; j < value.Len(); j++ {
				err = encode(buf, value.Index(j), valType, dataOnly)
				if err != nil {
					return
				}
			}
		}
	case reflect.String:
		writeVarNum(buf, valType)
		s := value.String()
		writeVarNum(buf, uint64(len(s)))
		_, err = buf.Write([]byte(s))
		if err != nil {
			return
		}
	case reflect.Ptr:
		err = encode(buf, value.Elem(), valType, dataOnly)
		if err != nil {
			return
		}
	case reflect.Struct:
		childBuf := new(bytes.Buffer)
		err = encodeStruct(childBuf, value, dataOnly)
		if err != nil {
			return
		}
		writeVarNum(buf, valType)
		writeVarNum(buf, uint64(childBuf.Len()))
		_, err = childBuf.WriteTo(buf)
		if err != nil {
			return
		}
	default:
		err = ErrNotSupported
		return
	}
	return
}

func encodeStruct(buf Writer, structValue reflect.Value, dataOnly bool) (err error) {
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)
		var tag *structTag
		tag, err = parseTag(structValue.Type().Field(i).Tag)
		if err != nil {
			return
		}
		if tag.Implicit ||
			dataOnly && tag.NotData ||
			tag.Optional && reflect.DeepEqual(fieldValue.Interface(), reflect.Zero(fieldValue.Type()).Interface()) {
			continue
		}

		err = encode(buf, fieldValue, tag.Type, dataOnly)
		if err != nil {
			return
		}
	}
	return
}
