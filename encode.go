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

func Marshal(buf Writer, i interface{}, valType uint64) error {
	return encode(buf, reflect.ValueOf(i), valType)
}

// return data bytes, * marked field is skipped
func Data(buf Writer, i interface{}) (err error) {
	structValue := reflect.Indirect(reflect.ValueOf(i))
	if structValue.Kind() != reflect.Struct {
		err = fmt.Errorf("not struct")
		return
	}
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)
		var tag *structTag
		tag, err = parseTag(structValue, i)
		if err != nil {
			return
		}
		if tag.NotData || tag.Optional && reflect.DeepEqual(fieldValue.Interface(), reflect.Zero(fieldValue.Type()).Interface()) {
			continue
		}

		err = encode(buf, fieldValue, tag.Type)
		if err != nil {
			return
		}
	}
	return
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

func encodeString(buf Writer, v string) (err error) {
	writeVarNum(buf, uint64(len(v)))
	_, err = buf.Write([]byte(v))
	return
}

func encodeBytes(buf Writer, v []byte) (err error) {
	writeVarNum(buf, uint64(len(v)))
	_, err = buf.Write(v)
	return
}

type structTag struct {
	Type     uint64
	Optional bool // ?
	NotData  bool // *
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
	switch value.Kind() {
	case reflect.Bool:
		writeVarNum(buf, valType)
		// no length
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
			err = encodeBytes(buf, value.Bytes())
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
		err = encodeString(buf, value.String())
		if err != nil {
			return
		}
	case reflect.Ptr:
		err = encode(buf, value.Elem(), valType)
		if err != nil {
			return
		}
	case reflect.Struct:
		writeVarNum(buf, valType)
		err = encodeStruct(buf, value)
		if err != nil {
			return
		}
	default:
		err = fmt.Errorf("invalid type: %v", value.Kind())
		return
	}
	return
}

func encodeStruct(buf Writer, structValue reflect.Value) (err error) {
	childBuf := new(bytes.Buffer)
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)
		var tag *structTag
		tag, err = parseTag(structValue, i)
		if err != nil {
			return
		}
		if tag.Optional && reflect.DeepEqual(fieldValue.Interface(), reflect.Zero(fieldValue.Type()).Interface()) {
			continue
		}

		err = encode(childBuf, fieldValue, tag.Type)
		if err != nil {
			return
		}
	}
	writeVarNum(buf, uint64(childBuf.Len()))
	childBuf.WriteTo(buf)
	return
}
