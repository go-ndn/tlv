package tlv

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

func Unmarshal(buf PeekReader, i interface{}, valType uint64) error {
	return decode(buf, reflect.ValueOf(i), valType)
}

func readTLV(buf Reader) (t uint64, v []byte, err error) {
	t, err = readVarNum(buf)
	if err != nil {
		return
	}
	l, err := readVarNum(buf)
	if err != nil {
		return
	}
	v = make([]byte, int(l))
	_, err = io.ReadFull(buf, v)
	return
}

func readVarNum(buf io.Reader) (v uint64, err error) {
	b := make([]byte, 1)
	_, err = io.ReadFull(buf, b)
	if err != nil {
		return
	}
	switch b[0] {
	case 0xFF:
		err = binary.Read(buf, binary.BigEndian, &v)
	case 0xFE:
		var v32 uint32
		err = binary.Read(buf, binary.BigEndian, &v32)
		v = uint64(v32)
	case 0xFD:
		var v16 uint16
		err = binary.Read(buf, binary.BigEndian, &v16)
		v = uint64(v16)
	default:
		v = uint64(b[0])
	}
	return
}

func decodeUint64(buf *bytes.Buffer) (v uint64, err error) {
	switch buf.Len() {
	case 8:
		err = binary.Read(buf, binary.BigEndian, &v)
	case 4:
		var v32 uint32
		err = binary.Read(buf, binary.BigEndian, &v32)
		v = uint64(v32)
	case 2:
		var v16 uint16
		err = binary.Read(buf, binary.BigEndian, &v16)
		v = uint64(v16)
	case 1:
		var v8 uint8
		err = binary.Read(buf, binary.BigEndian, &v8)
		v = uint64(v8)
	}
	return
}

func peekType(buf PeekReader) (t uint64, err error) {
	// at most 1 + 8 bytes
	b, _ := buf.Peek(9)
	t, err = readVarNum(bytes.NewBuffer(b))
	return
}

func decode(buf PeekReader, value reflect.Value, valType uint64) (err error) {
	switch value.Kind() {
	case reflect.Ptr:
		if value.CanSet() {
			// uninitialized
			elem := reflect.New(value.Type().Elem())
			err = decode(buf, elem.Elem(), valType)
			if err != nil {
				return
			}
			value.Set(elem)
		} else {
			err = decode(buf, value.Elem(), valType)
			if err != nil {
				return
			}
		}
		return
	case reflect.Slice:
		switch value.Type().Elem().Kind() {
		case reflect.Uint8:
		default:
			for {
				elem := reflect.New(value.Type().Elem()).Elem()
				err = decode(buf, elem, valType)
				if err != nil {
					// try and fail approach
					err = nil
					break
				}
				value.Set(reflect.Append(value, elem))
			}
			return
		}
	}

	t, err := peekType(buf)
	if err != nil {
		err = fmt.Errorf("peek nothing: %v", value.Type())
		return
	}
	if t != valType {
		err = fmt.Errorf("expected type: %v, actual type: %v", valType, t)
		return
	}

	_, v, err := readTLV(buf)
	if err != nil {
		return
	}

	switch value.Kind() {
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Uint64:
		var num uint64
		num, err = decodeUint64(bytes.NewBuffer(v))
		if err != nil {
			return
		}
		value.SetUint(num)
	case reflect.Slice:
		switch value.Type().Elem().Kind() {
		case reflect.Uint8:
			value.SetBytes(v)
		}
	case reflect.String:
		value.SetString(string(v))
	case reflect.Struct:
		err = decodeStruct(bufio.NewReader(bytes.NewBuffer(v)), value)
		if err != nil {
			return
		}
	default:
		err = fmt.Errorf("invalid type: %v", value.Kind())
		return
	}
	return
}

func decodeStruct(buf PeekReader, structValue reflect.Value) (err error) {
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)
		var tag *structTag
		tag, err = parseTag(structValue, i)
		if err != nil {
			return
		}
		err = decode(buf, fieldValue, tag.Type)
		if err != nil {
			if tag.Optional {
				err = nil
			} else {
				return
			}
		}
	}
	return
}
