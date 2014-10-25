package tlv

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

// The max size for tlv is 8800.
//
// (1) One "common" size of Ethernet jumbo packets is 9000 octets
//
// (2) It is generally sufficient to carry an 8192 byte payload in a content object
//
// (3) 8800 bytes was a message size limit in ONC-RPC over UDP
//
// (4) Some OSs have a limited default UDP packet size (MacOS: net.inet.udp.maxdgram: 9216) and/or a limited space for receive buffers (MacOS: net.inet.udp.recvspace: 42080)
//
// (5) When a ContentObject is signed it is not known whether the transmission path will be UDP / TCP / ..
const (
	maxSize = 8800
)

// Unmarshal reads arbitrary data from tlv.PeekReader
func Unmarshal(buf PeekReader, i interface{}, valType uint64) error {
	return decode(buf, reflect.ValueOf(i), valType)
}

func readTLV(buf io.Reader) (t uint64, v []byte, err error) {
	t, err = readVarNum(buf)
	if err != nil {
		return
	}
	l, err := readVarNum(buf)
	if err != nil {
		return
	}
	if l > maxSize {
		err = fmt.Errorf("tlv over max size")
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

func decodeValue(v []byte, value reflect.Value) (err error) {
	if r, ok := value.Interface().(ReadValueFrom); ok {
		return r.ReadValueFrom(bufio.NewReader(bytes.NewBuffer(v)))
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
		default:
			elem := reflect.New(value.Type().Elem()).Elem()
			err = decodeValue(v, elem)
			if err != nil {
				return
			}
			value.Set(reflect.Append(value, elem))
		}
	case reflect.String:
		value.SetString(string(v))
	case reflect.Ptr:
		if value.CanSet() {
			// uninitialized
			elem := reflect.New(value.Type().Elem())
			err = decodeValue(v, elem.Elem())
			if err != nil {
				return
			}
			value.Set(elem)
		} else {
			err = decodeValue(v, value.Elem())
			if err != nil {
				return
			}
		}
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

func decode(buf PeekReader, value reflect.Value, valType uint64) (err error) {
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
	err = decodeValue(v, value)
	if err != nil {
		return
	}
	if value.Kind() == reflect.Slice && value.Type().Elem().Kind() != reflect.Uint8 {
		decode(buf, value, valType)
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
			if tag.Implicit || tag.Optional {
				err = nil
			} else {
				return
			}
		}
	}
	return
}
