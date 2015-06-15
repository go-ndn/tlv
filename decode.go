package tlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
)

// The max size for tlv is 8800.
//
// 1. One "common" size of Ethernet jumbo packets is 9000 octets
// 2. It is generally sufficient to carry an 8192 byte payload in a content object
// 3. 8800 bytes was a message size limit in ONC-RPC over UDP
// 4. Some OSs have a limited default UDP packet size (MacOS: net.inet.udp.maxdgram: 9216) and/or a limited space for receive buffers (MacOS: net.inet.udp.recvspace: 42080)
// 5. When a ContentObject is signed it is not known whether the transmission path will be UDP / TCP / ..
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
	// redirect is required for ptr to slice
	return decode(r, reflect.Indirect(reflect.ValueOf(i)), valType, false)
}

func UnmarshalByte(b []byte, i interface{}, valType uint64) error {
	return Unmarshal(NewReader(bytes.NewReader(b)), i, valType)
}

func readTLV(r io.Reader) (t uint64, v []byte, err error) {
	t, err = ReadVarNum(r)
	if err != nil {
		return
	}
	l, err := ReadVarNum(r)
	if err != nil {
		return
	}
	if l > maxSize {
		err = ErrPacketTooLarge
		return
	}
	v = make([]byte, l)
	_, err = io.ReadFull(r, v)
	return
}

func ReadVarNum(r io.Reader) (v uint64, err error) {
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

func decodeValue(v []byte, value reflect.Value, extended bool) (err error) {
	switch value.Kind() {
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Uint64:
		value.SetUint(decodeUint64(v))
	case reflect.Slice:
		elemType := value.Type().Elem()
		switch elemType.Kind() {
		case reflect.Uint8:
			value.SetBytes(v)
		case reflect.Struct:
			if extended {
				var valTypes []uint64
				err = walkStruct(elemType, func(tag *structTag, _ int) error {
					valTypes = append(valTypes, tag.Type)
					return nil
				})
				if err != nil {
					return
				}
				r := NewReader(bytes.NewReader(v))
				for {
					t := r.Peek()
					if t == 0 {
						return
					}
					for _, valType := range valTypes {
						if t == valType {
							goto DECODE
						}
					}
					err = ErrUnexpectedType
					return
				DECODE:
					elem := reflect.New(elemType).Elem()
					err = decodeStruct(r, elem)
					if err != nil {
						return
					}
					value.Set(reflect.Append(value, elem))
				}
			}
			fallthrough
		default:
			elem := reflect.New(elemType).Elem()
			err = decodeValue(v, elem, false)
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
		err = decodeValue(v, value.Elem(), false)
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

func decode(r Reader, value reflect.Value, valType uint64, extended bool) (err error) {
	var progress bool
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
		err = decodeValue(v, value, extended)
		if err != nil {
			break
		}
		progress = true
		if value.Kind() != reflect.Slice || value.Type().Elem().Kind() == reflect.Uint8 || extended {
			return
		}
	}
	if progress {
		err = nil
	}
	return
}

func decodeStruct(r Reader, structValue reflect.Value) error {
	return walkStruct(structValue.Type(), func(tag *structTag, i int) (err error) {
		err = decode(r, structValue.Field(i), tag.Type, tag.Extended)
		if err != nil && tag.Optional {
			err = nil
		}
		return
	})
}
