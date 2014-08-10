package tlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
)

func Unmarshal(buf *bytes.Buffer, i interface{}, valType uint64) error {
	return decode(buf, reflect.ValueOf(i), valType)
}

func readTLV(buf *bytes.Buffer) (t uint64, v *bytes.Buffer, err error) {
	t, err = ReadBytes(buf)
	if err != nil {
		return
	}
	l, err := ReadBytes(buf)
	if err != nil {
		return
	}
	v = bytes.NewBuffer(buf.Next(int(l)))
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

func decode(buf *bytes.Buffer, value reflect.Value, valType uint64) (err error) {
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
	var t uint64
	var v *bytes.Buffer
	t, v, err = readTLV(buf)
	if err != nil {
		return
	}
	if t != valType {
		err = errors.New(fmt.Sprintf("type does not match: %d != %d", valType, t))
		// recover
		rec := new(bytes.Buffer)
		WriteBytes(rec, t)
		WriteBytes(rec, uint64(v.Len()))
		rec.ReadFrom(v)
		rec.ReadFrom(buf)
		*buf = *rec
		return
	}

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
			value.SetBytes(v.Bytes())
		}
	case reflect.String:
		value.SetString(v.String())
	case reflect.Struct:
		err = decodeStruct(v, value)
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
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)
		var valType uint64
		valType, err = Type(structValue, i)
		if err != nil {
			return
		}

		err = decode(buf, fieldValue, valType)
		if err != nil {
			if optional(structValue, i) {
				err = nil
			} else {
				return
			}
		}
	}
	return
}
