package tlv

import (
	"bytes"
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
// '?' after type number means that this field is optional.
// If the value of optional tlv is Zero value, the whole tlv is not written.
//
// '*' after type number means that this field is not data (i.e. signature).
func Marshal(buf Writer, i interface{}, valType uint64) error {
	return encode(buf, reflect.ValueOf(i), valType)
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
}

func parseTag(v reflect.Value, i int) (tag *structTag, err error) {
	s := v.Type().Field(i).Tag.Get("tlv")
	if s == "" {
		err = fmt.Errorf("type not found: %v %v", v.Type().Name(), v.Type().Field(i).Name)
		return
	}
	tag = new(structTag)
	if strings.Contains(s, "?") {
		tag.Optional = true
	}
	if strings.Contains(s, "*") {
		tag.NotData = true
	}
	tag.Type, err = strconv.ParseUint(strings.TrimRight(s, "*?"), 10, 64)
	return
}

func encode(buf Writer, value reflect.Value, valType uint64) (err error) {
	if w, ok := value.Interface().(WriteValueTo); ok {
		childBuf := new(bytes.Buffer)
		err = w.WriteValueTo(childBuf)
		if err != nil {
			return
		}
		writeVarNum(buf, valType)
		writeVarNum(buf, uint64(childBuf.Len()))
		_, err = childBuf.WriteTo(buf)
		return
	}
	switch value.Kind() {
	case reflect.Bool:
		writeVarNum(buf, valType)
		writeVarNum(buf, 0)
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
				err = encode(buf, value.Index(j), valType)
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
		err = encode(buf, value.Elem(), valType)
		if err != nil {
			return
		}
	case reflect.Struct:
		childBuf := new(bytes.Buffer)
		err = encodeStruct(childBuf, value, false)
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
		err = fmt.Errorf("invalid type: %v", value.Kind())
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
		if dataOnly && tag.NotData ||
			tag.Optional && reflect.DeepEqual(fieldValue.Interface(), reflect.Zero(fieldValue.Type()).Interface()) {
			continue
		}

		err = encode(buf, fieldValue, tag.Type)
		if err != nil {
			return
		}
	}
	return
}
