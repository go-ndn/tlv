package tlv

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
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
		return fmt.Errorf("not struct")
	}
	return encodeStruct(buf, value, true)
}

func writeVarNum(buf Writer, v uint64) (err error) {
	switch {
	case v > math.MaxUint32:
		buf.Write([]byte{0xFF})
		err = binary.Write(buf, binary.BigEndian, v)
	case v > math.MaxUint16:
		buf.Write([]byte{0xFE})
		err = binary.Write(buf, binary.BigEndian, uint32(v))
	case v > math.MaxUint8-3:
		buf.Write([]byte{0xFD})
		err = binary.Write(buf, binary.BigEndian, uint16(v))
	default:
		err = binary.Write(buf, binary.BigEndian, uint8(v))
	}
	return
}

func encodeUint64(buf Writer, v uint64) (err error) {
	switch {
	case v > math.MaxUint32:
		writeVarNum(buf, 8)
		err = binary.Write(buf, binary.BigEndian, v)
	case v > math.MaxUint16:
		writeVarNum(buf, 4)
		err = binary.Write(buf, binary.BigEndian, uint32(v))
	case v > math.MaxUint8:
		writeVarNum(buf, 2)
		err = binary.Write(buf, binary.BigEndian, uint16(v))
	default:
		writeVarNum(buf, 1)
		err = binary.Write(buf, binary.BigEndian, uint8(v))
	}
	return
}

type structTag struct {
	Type     uint64
	Optional bool
	NotData  bool
	Implicit bool
}

func parseTag(v reflect.Value, i int) (tag *structTag, err error) {
	s := v.Type().Field(i).Tag.Get("tlv")
	if s == "" {
		err = fmt.Errorf("type not found: %s %s", v.Type().Name(), v.Type().Field(i).Name)
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
			writeVarNum(buf, 0)
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
		err = fmt.Errorf("invalid type: %s", value.Kind())
		return
	}
	return
}

func encodeStruct(buf Writer, structValue reflect.Value, dataOnly bool) (err error) {
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)
		var tag *structTag
		tag, err = parseTag(structValue, i)
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
