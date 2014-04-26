package tlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	//"io"
	"reflect"
)

func Unmarshal(raw []byte, i interface{}, rootType uint64) (err error) {
	buf := bytes.NewBuffer(raw)
	t, v, err := readTLV(buf)
	if err != nil {
		return
	}
	if t != rootType {
		err = errors.New(fmt.Sprintf("type does not match: %d != %d", rootType, t))
		return
	}
	err = decodeStruct(bytes.NewBuffer(v), reflect.ValueOf(i))
	return
}

func readTLV(buf *bytes.Buffer) (t uint64, v []byte, err error) {
	t, err = readBytes(buf)
	if err != nil {
		return
	}
	l, err := readBytes(buf)
	if err != nil {
		return
	}
	v = buf.Next(int(l))
	return
}

func readBytes(buf *bytes.Buffer) (v uint64, err error) {
	b, err := buf.ReadByte()
	if err != nil {
		return
	}
	switch b {
	case 0xFF:
		err = binary.Read(buf, binary.BigEndian, v)
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

func decodeStruct(buf *bytes.Buffer, structValue reflect.Value) (err error) {
	if structValue.Kind() == reflect.Ptr {
		structValue = structValue.Elem()
	}
	if structValue.Kind() != reflect.Struct {
		err = errors.New("invalid type: " + structValue.Kind().String())
		return
	}
	var t uint64
	var v []byte
	ok := true
	for i := 0; i < structValue.NumField(); i++ {
		// eof sink
		if err != nil {
			if optional(structValue, i) {
				if i == structValue.NumField()-1 {
					err = nil
					return
				}
				continue
			} else {
				return
			}
		}
		fieldValue := structValue.Field(i)
		var valType []uint64
		valType, err = typeValue(structValue, i)
		if err != nil {
			return
		}
		// read next tlv
		if ok {
			t, v, err = readTLV(buf)
			if err != nil {
				continue
			}
		}
		// type does not match
		if valType[0] != t {
			if optional(structValue, i) {
				ok = false
				continue
			} else {
				err = errors.New(fmt.Sprintf("type does not match: %d != %d", valType, t))
				return
			}
		}
		// can continue
		ok = true
		switch fieldValue.Kind() {
		case reflect.Bool:
			fieldValue.SetBool(true)
		case reflect.Uint64:
			var num uint64
			num, err = decodeUint64(v)
			if err != nil {
				return
			}
			fieldValue.SetUint(num)
		case reflect.Slice:
			switch fieldValue.Type().Elem().Kind() {
			case reflect.Slice:
				sliceBuf := bytes.NewBuffer(v)
				for sliceBuf.Len() != 0 {
					var t uint64
					var v []byte
					t, v, err = readTLV(sliceBuf)
					if err != nil {
						return
					}
					if valType[1] != t {
						err = errors.New(fmt.Sprintf("subtype does not match: %d != %d", valType, t))
						return
					}
					fieldValue.Set(reflect.Append(fieldValue, reflect.ValueOf(v)))
				}
			case reflect.Uint8:
				fieldValue.SetBytes(v)
			case reflect.Ptr:
				fallthrough
			case reflect.Struct:
				for {
					elem := reflect.New(fieldValue.Type().Elem())
					if fieldValue.Type().Elem().Kind() == reflect.Struct {
						elem = elem.Elem()
					}
					err = decodeStruct(bytes.NewBuffer(v), elem)
					if err != nil {
						return
					}
					fieldValue.Set(reflect.Append(fieldValue, elem))
					t, v, err = readTLV(buf)
					if err != nil {
						break
					}
					// mismatch, try next field
					if valType[0] != t {
						ok = false
						break
					}
				}
			default:
				err = errors.New("invalid slice type: " + fieldValue.Type().String())
				return
			}
		case reflect.String:
			fieldValue.SetString(string(v))
		case reflect.Ptr:
			fallthrough
		case reflect.Struct:
			err = decodeStruct(bytes.NewBuffer(v), fieldValue)
			if err != nil {
				return
			}
		default:
			err = errors.New("invalid type: " + fieldValue.Kind().String())
			return
		}
	}
	return
}
