package tlv

import (
	"encoding"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
)

var (
	ErrPacketTooLarge = errors.New("exceed max size")
	ErrNotSupported   = errors.New("feature not supported")
	ErrUnexpectedType = errors.New("type not match")
)

type Reader interface {
	Peek() uint64
	Read(interface{}, uint64) error
}

type ReadFrom interface {
	ReadFrom(Reader) error
}

type reader struct {
	io.Reader
	b     []byte
	valid bool
}

func NewReader(r io.Reader) Reader {
	return &reader{
		Reader: r,
		b:      make([]byte, maxSize),
	}
}

func (r *reader) Peek() uint64 {
	if !r.valid {
		r.fill()
	}
	if !r.valid {
		return 0
	}
	_, v := readVarNum(r.b)
	return v
}

func fillVarNum(r io.Reader, b []byte) (n int, err error) {
	_, err = io.ReadFull(r, b[:1])
	if err != nil {
		return
	}
	switch b[0] {
	case 0xFF:
		n = 9
	case 0xFE:
		n = 5
	case 0xFD:
		n = 3
	default:
		n = 1
	}
	_, err = io.ReadFull(r, b[1:n])
	return
}

func (r *reader) fill() (err error) {
	var n int
	nn, err := fillVarNum(r.Reader, r.b[n:])
	if err != nil {
		return
	}
	n += nn

	nn, err = fillVarNum(r.Reader, r.b[n:])
	if err != nil {
		return
	}
	_, l := readVarNum(r.b[n:])
	n += nn

	if l > uint64(len(r.b[n:])) {
		err = ErrPacketTooLarge
		return
	}
	_, err = io.ReadFull(r.Reader, r.b[n:n+int(l)])
	if err != nil {
		return
	}
	r.valid = true
	return
}

func (r *reader) Read(v interface{}, t uint64) (err error) {
	if !r.valid {
		r.fill()
	}
	if !r.valid {
		err = io.EOF
		return
	}
	// redirect is required for ptr to slice
	_, err = readTLV(r.b, t, reflect.Indirect(reflect.ValueOf(v)))
	r.valid = false
	return
}

func readVarNum(b []byte) (n int, v uint64) {
	switch b[0] {
	case 0xFF:
		v = binary.BigEndian.Uint64(b[1:])
		n = 9
	case 0xFE:
		v = uint64(binary.BigEndian.Uint32(b[1:]))
		n = 5
	case 0xFD:
		v = uint64(binary.BigEndian.Uint16(b[1:]))
		n = 3
	default:
		v = uint64(b[0])
		n = 1
	}
	return
}

func readUint64(b []byte) uint64 {
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

func readStruct(v []byte, structValue reflect.Value) error {
	var n int
	return walkStruct(structValue.Type(), func(tag *structTag, i int) (err error) {
		nn, err := readTLV(v[n:], tag.Type, structValue.Field(i))
		if err != nil {
			if tag.Optional {
				err = nil
			} else {
				return
			}
		}
		n += nn
		return
	})
}

var (
	typeBinaryUnmarshaler = reflect.TypeOf((*encoding.BinaryUnmarshaler)(nil)).Elem()
)

func readValue(v []byte, value reflect.Value) (err error) {
	if value.Type().Implements(typeBinaryUnmarshaler) {
		err = value.Interface().(encoding.BinaryUnmarshaler).UnmarshalBinary(v)
		return
	}
	switch value.Kind() {
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Uint64:
		value.SetUint(readUint64(v))
	case reflect.Slice:
		elemType := value.Type().Elem()
		switch elemType.Kind() {
		case reflect.Uint8:
			b := make([]byte, len(v))
			copy(b, v)
			value.SetBytes(b)
		default:
			elem := reflect.New(elemType).Elem()
			err = readValue(v, elem)
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
		err = readValue(v, value.Elem())
	case reflect.Struct:
		err = readStruct(v, value)
	default:
		err = ErrNotSupported
	}
	return
}

func readTLV(b []byte, expectType uint64, value reflect.Value) (n int, err error) {
	var progress bool

	for len(b[n:]) != 0 {
		nn, t := readVarNum(b[n:])
		if t != expectType {
			err = ErrUnexpectedType
			break
		}
		n += nn
		nn, l := readVarNum(b[n:])
		n += nn
		v := b[n : n+int(l)]
		n += int(l)
		err = readValue(v, value)
		if err != nil {
			break
		}
		progress = true
		if value.Kind() != reflect.Slice || value.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
	}
	if progress {
		err = nil
	}
	return
}
