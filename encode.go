package tlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"math"
	"reflect"
	"strconv"
	"strings"
)

func Marshal(i interface{}, rootType uint64) (raw []byte, err error) {
	buf := new(bytes.Buffer)
	WriteBytes(buf, rootType)
	structValue := reflect.ValueOf(i)
	if structValue.Kind() == reflect.Ptr {
		structValue = structValue.Elem()
	}
	if structValue.Kind() != reflect.Struct {
		err = errors.New("invalid type: " + structValue.Kind().String())
		return
	}
	err = encodeStruct(buf, structValue)
	if err != nil {
		return
	}
	raw = buf.Bytes()
	return
}

func Hash(i interface{}, hasher hash.Hash, index []int) (sum []byte, err error) {
	buf := new(bytes.Buffer)
	structValue := reflect.ValueOf(i)
	if structValue.Kind() == reflect.Ptr {
		structValue = structValue.Elem()
	}
	if structValue.Kind() != reflect.Struct {
		err = errors.New("invalid type: " + structValue.Kind().String())
		return
	}
	err = encodeField(buf, structValue, index)
	if err != nil {
		return
	}
	hasher.Write(buf.Bytes())
	sum = hasher.Sum(nil)
	return
}

func WriteBytes(buf *bytes.Buffer, v uint64) (err error) {
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
		WriteBytes(buf, 8)
		err = binary.Write(buf, binary.BigEndian, v)
	case v > math.MaxUint16:
		WriteBytes(buf, 4)
		err = binary.Write(buf, binary.BigEndian, uint32(v))
	case v > math.MaxUint8:
		WriteBytes(buf, 2)
		err = binary.Write(buf, binary.BigEndian, uint16(v))
	default:
		WriteBytes(buf, 1)
		err = binary.Write(buf, binary.BigEndian, uint8(v))
	}
	return
}

func encodeString(buf *bytes.Buffer, v string) (err error) {
	WriteBytes(buf, uint64(len(v)))
	_, err = buf.WriteString(v)
	return
}

func encodeBytes(buf *bytes.Buffer, v []byte) (err error) {
	WriteBytes(buf, uint64(len(v)))
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
	case reflect.Ptr:
		fallthrough
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

func encodeField(buf *bytes.Buffer, structValue reflect.Value, index []int) (err error) {
	for _, i := range index {
		fieldValue := structValue.Field(i)
		if optional(structValue, i) && zero(fieldValue) {
			continue
		}
		var valType []uint64
		valType, err = typeValue(structValue, i)
		if err != nil {
			return
		}
		WriteBytes(buf, valType[0])
		switch fieldValue.Kind() {
		case reflect.Bool:
			// no length
			WriteBytes(buf, 0)
		case reflect.Uint64:
			err = encodeUint64(buf, fieldValue.Uint())
			if err != nil {
				return
			}
		case reflect.Slice:
			switch fieldValue.Type().Elem().Kind() {
			case reflect.Slice:
				sliceBuf := new(bytes.Buffer)
				for j := 0; j < fieldValue.Len(); j++ {
					WriteBytes(sliceBuf, valType[1])
					err = encodeBytes(sliceBuf, fieldValue.Index(j).Bytes())
					if err != nil {
						return
					}
				}
				WriteBytes(buf, uint64(sliceBuf.Len()))
				buf.ReadFrom(sliceBuf)
			case reflect.Uint8:
				err = encodeBytes(buf, fieldValue.Bytes())
				if err != nil {
					return
				}
			case reflect.Ptr:
				fallthrough
			case reflect.Struct:
				for j := 0; j < fieldValue.Len(); j++ {
					err = encodeStruct(buf, fieldValue.Index(j))
					if err != nil {
						return
					}
					if j != fieldValue.Len()-1 {
						WriteBytes(buf, valType[0])
					}
				}
			default:
				err = errors.New("invalid slice type: " + fieldValue.Type().String())
				return
			}
		case reflect.String:
			err = encodeString(buf, fieldValue.String())
			if err != nil {
				return
			}
		case reflect.Ptr:
			fallthrough
		case reflect.Struct:
			err = encodeStruct(buf, fieldValue)
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

func encodeStruct(buf *bytes.Buffer, structValue reflect.Value) (err error) {
	childBuf := new(bytes.Buffer)
	index := []int{}
	for i := 0; i < structValue.NumField(); i++ {
		index = append(index, i)
	}
	err = encodeField(childBuf, structValue, index)
	if err != nil {
		return
	}
	WriteBytes(buf, uint64(childBuf.Len()))
	buf.ReadFrom(childBuf)
	return
}
