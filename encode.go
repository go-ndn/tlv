package tlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
)

func Marshal(i interface{}, rootType uint64) ([]byte, error) {
	buf := new(bytes.Buffer)
	writeBytes(buf, rootType)
	err := encodeStruct(buf, reflect.ValueOf(i))
	return buf.Bytes(), err
}

func writeBytes(buf *bytes.Buffer, v uint64) (err error) {
	switch {
	case v > math.MaxUint32:
		buf.WriteByte(0xFF)
		err = binary.Write(buf, binary.BigEndian, v)
	case v > math.MaxUint16:
		buf.WriteByte(0xFE)
		err = binary.Write(buf, binary.BigEndian, uint32(v))
	case v > math.MaxUint8-3:
		buf.WriteByte(0xFD)
		err = binary.Write(buf, binary.BigEndian, uint16(v))
	default:
		err = binary.Write(buf, binary.BigEndian, uint8(v))
	}
	return
}

func encodeUint64(buf *bytes.Buffer, v uint64) (err error) {
	switch {
	case v > math.MaxUint32:
		writeBytes(buf, 8)
		err = binary.Write(buf, binary.BigEndian, v)
	case v > math.MaxUint16:
		writeBytes(buf, 4)
		err = binary.Write(buf, binary.BigEndian, uint32(v))
	case v > math.MaxUint8:
		writeBytes(buf, 2)
		err = binary.Write(buf, binary.BigEndian, uint16(v))
	default:
		writeBytes(buf, 1)
		err = binary.Write(buf, binary.BigEndian, uint8(v))
	}
	return
}

func encodeString(buf *bytes.Buffer, v string) (err error) {
	writeBytes(buf, uint64(len(v)))
	_, err = buf.WriteString(v)
	return
}

func encodeBytes(buf *bytes.Buffer, v []byte) (err error) {
	writeBytes(buf, uint64(len(v)))
	_, err = buf.Write(v)
	return
}

func typeValue(v reflect.Value, i int) (t []uint64, err error) {
	for _, part := range strings.Split(strings.TrimSuffix(v.Type().Field(i).Tag.Get("tlv"), ",-"), ",") {
		var i uint64
		i, err = strconv.ParseUint(part, 10, 64)
		if err != nil {
			return
		}
		t = append(t, i)
	}
	return
}

func optional(v reflect.Value, i int) bool {
	return strings.HasSuffix(v.Type().Field(i).Tag.Get("tlv"), ",-")
}

func zero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool() == false
	case reflect.Uint64:
		return v.Uint() == 0
	case reflect.Slice:
		return v.IsNil()
	case reflect.String:
		return v.String() == ""
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !zero(v.Field(i)) {
				return false
			}
		}
		return true
	}
	return false
}

func encodeStruct(buf *bytes.Buffer, structValue reflect.Value) (err error) {
	if structValue.Kind() == reflect.Ptr {
		structValue = structValue.Elem()
	}
	if structValue.Kind() != reflect.Struct {
		err = errors.New("invalid type: " + structValue.Kind().String())
		return
	}
	childBuf := new(bytes.Buffer)
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)
		if optional(structValue, i) && zero(fieldValue) {
			continue
		}
		var valType []uint64
		valType, err = typeValue(structValue, i)
		if err != nil {
			return
		}
		writeBytes(childBuf, valType[0])
		switch fieldValue.Kind() {
		case reflect.Bool:
			// no length
			writeBytes(childBuf, 0)
		case reflect.Uint64:
			err = encodeUint64(childBuf, fieldValue.Uint())
			if err != nil {
				return
			}
		case reflect.Slice:
			switch fieldValue.Type().Elem().Kind() {
			case reflect.Slice:
				sliceBuf := new(bytes.Buffer)
				for j := 0; j < fieldValue.Len(); j++ {
					writeBytes(sliceBuf, valType[1])
					err = encodeBytes(sliceBuf, fieldValue.Index(j).Bytes())
					if err != nil {
						return
					}
				}
				writeBytes(childBuf, uint64(sliceBuf.Len()))
				childBuf.ReadFrom(sliceBuf)
			case reflect.Uint8:
				err = encodeBytes(childBuf, fieldValue.Bytes())
				if err != nil {
					return
				}
			case reflect.Ptr:
				fallthrough
			case reflect.Struct:
				for j := 0; j < fieldValue.Len(); j++ {
					err = encodeStruct(childBuf, fieldValue.Index(j))
					if err != nil {
						return
					}
					if j != fieldValue.Len()-1 {
						writeBytes(childBuf, valType[0])
					}
				}
			default:
				err = errors.New("invalid slice type: " + fieldValue.Type().String())
				return
			}
		case reflect.String:
			err = encodeString(childBuf, fieldValue.String())
			if err != nil {
				return
			}
		case reflect.Ptr:
			fallthrough
		case reflect.Struct:
			err = encodeStruct(childBuf, fieldValue)
			if err != nil {
				return
			}
		default:
			err = errors.New("invalid type: " + fieldValue.Kind().String())
			return
		}
	}
	writeBytes(buf, uint64(childBuf.Len()))
	buf.ReadFrom(childBuf)
	return
}
