package tlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	//"io"
	"reflect"
)

func Unmarshal(raw []byte, i interface{}, valType uint64) (err error) {
	buf := bytes.NewBuffer(raw)
	for buf.Len() != 0 {
		var t uint64
		var v []byte
		t, v, err = readTLV(buf)
		if err != nil {
			return
		}
		if valType != t {
			err = errors.New(fmt.Sprintf("type does not match: %d != %d", valType, t))
			return
		}
		err = decode(reflect.ValueOf(i), v)
		if err != nil {
			return
		}
	}
	return
}

func readTLV(buf *bytes.Buffer) (t uint64, v []byte, err error) {
	t, err = ReadBytes(buf)
	if err != nil {
		return
	}
	l, err := ReadBytes(buf)
	if err != nil {
		return
	}
	v = buf.Next(int(l))
	return
}

func ReadBytes(buf *bytes.Buffer) (v uint64, err error) {
	b, err := buf.ReadByte()
	if err != nil {
		return
	}
	switch b {
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
		v = uint64(b)
	}
	return
}

func decodeUint64(raw []byte) (v uint64, err error) {
	buf := bytes.NewBuffer(raw)
	switch len(raw) {
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

func canIgnoreError(structValue reflect.Value, i int) bool {
	if optional(structValue, i) {
		return true
	}
	if structValue.Field(i).Kind() != reflect.Slice {
		return false
	}
	return structValue.Field(i).Type().Elem().Kind() != reflect.Uint8
}

func decode(value reflect.Value, v []byte) (err error) {
	switch value.Kind() {
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Uint64:
		var num uint64
		num, err = decodeUint64(v)
		if err != nil {
			return
		}
		value.SetUint(num)
	case reflect.Slice:
		switch value.Type().Elem().Kind() {
		case reflect.Uint8:
			value.SetBytes(v)
		default:
			elem := reflect.New(value.Type().Elem()).Elem()
			err = decode(elem, v)
			if err != nil {
				return
			}
			value.Set(reflect.Append(value, elem))
		}
	case reflect.String:
		value.SetString(string(v))
	case reflect.Ptr:
		value = value.Elem()
		fallthrough
	case reflect.Struct:
		err = decodeStruct(bytes.NewBuffer(v), value)
		if err != nil {
			return
		}
	default:
		err = errors.New("invalid type: " + value.Kind().String())
		return
	}
	return
}

func decodeStruct(buf *bytes.Buffer, structValue reflect.Value) (err error) {
	var t uint64
	var v []byte
	readNext := true
	for i := 0; i < structValue.NumField(); i++ {
		// read next tlv
		if readNext {
			t, v, err = readTLV(buf)
			if err != nil {
				for ; i < structValue.NumField(); i++ {
					if !canIgnoreError(structValue, i) {
						return
					}
				}
				err = nil
				return
			}
		}
		fieldValue := structValue.Field(i)
		var valType uint64
		valType, err = typeValue(structValue, i)
		if err != nil {
			return
		}
		// type does not match
		if valType != t {
			// 1. optional
			// 2. []struct
			if canIgnoreError(structValue, i) {
				readNext = false
				continue
			}
			err = errors.New(fmt.Sprintf("type does not match: %d != %d", valType, t))
			return
		}
		readNext = true
		err = decode(fieldValue, v)
		if err != nil {
			return
		}
		// continue match if not just []byte
		if fieldValue.Kind() == reflect.Slice && fieldValue.Type().Elem().Kind() != reflect.Uint8 {
			i--
		}
	}
	return
}
