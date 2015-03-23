package tlv

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
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

var (
	ErrPacketTooLarge = errors.New("exceed max size")
	ErrNotSupported   = errors.New("feature not supported")
	ErrUnexpectedType = errors.New("type not match")
)

// Unmarshal reads arbitrary data from tlv.Reader
func Unmarshal(r Reader, i interface{}, valType uint64) error {
	return decode(r, reflect.Indirect(reflect.ValueOf(i)), valType)
}

func readTLV(r io.Reader) (t uint64, v []byte, err error) {
	t, err = readVarNum(r)
	if err != nil {
		return
	}
	l, err := readVarNum(r)
	if err != nil {
		return
	}
	if l > maxSize {
		err = ErrPacketTooLarge
		return
	}
	v = make([]byte, int(l))
	_, err = io.ReadFull(r, v)
	return
}

func readVarNum(r io.Reader) (v uint64, err error) {
	b := make([]byte, 8)
	_, err = io.ReadFull(r, b[:1])
	if err != nil {
		return
	}
	switch b[0] {
	case 0xFF:
		_, err = io.ReadFull(r, b)
		if err != nil {
			return
		}
		v = binary.BigEndian.Uint64(b)
	case 0xFE:
		_, err = io.ReadFull(r, b[:4])
		if err != nil {
			return
		}
		v = uint64(binary.BigEndian.Uint32(b[:4]))
	case 0xFD:
		_, err = io.ReadFull(r, b[:2])
		if err != nil {
			return
		}
		v = uint64(binary.BigEndian.Uint16(b[:2]))
	default:
		v = uint64(b[0])
	}
	return
}

func decodeUint64(b []byte) uint64 {
	switch len(b) {
	case 8:
		return binary.BigEndian.Uint64(b)
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 1:
		return uint64(b[0])
	}
	return 0
}

func decodeValue(v []byte, value reflect.Value) (err error) {
	switch value.Kind() {
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Uint64:
		value.SetUint(decodeUint64(v))
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
			value.Set(reflect.New(value.Type().Elem()))
		}
		if i, ok := value.Interface().(encoding.BinaryUnmarshaler); ok {
			return i.UnmarshalBinary(v)
		}
		err = decodeValue(v, value.Elem())
		if err != nil {
			return
		}
	case reflect.Struct:
		err = decodeStruct(NewReader(bytes.NewReader(v)), value)
		if err != nil {
			return
		}
	default:
		err = ErrNotSupported
		return
	}
	return
}

func decode(r Reader, value reflect.Value, valType uint64) (err error) {
	var once bool
	for {
		if r.Peek() != valType {
			err = ErrUnexpectedType
			break
		}
		var v []byte
		_, v, err = r.Read()
		if err != nil {
			break
		}
		err = decodeValue(v, value)
		if err != nil {
			break
		}
		once = true
		if value.Kind() != reflect.Slice || value.Type().Elem().Kind() == reflect.Uint8 {
			break
		}
	}
	if once {
		err = nil
	}
	return
}

func decodeStruct(r Reader, structValue reflect.Value) (err error) {
	for i := 0; i < structValue.NumField(); i++ {
		field := structValue.Type().Field(i)
		if field.PkgPath != "" {
			// unexported
			continue
		}
		var tag *structTag
		tag, err = parseTag(field.Tag)
		if err != nil {
			return
		}
		fieldValue := structValue.Field(i)
		if tag.Implicit {
			continue
		}
		err = decode(r, fieldValue, tag.Type)
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
