package tlv

import (
	"encoding"
	"encoding/binary"
	"io"
	"math"
	"reflect"
)

// Writer encodes data in tlv.
type Writer interface {
	Write(interface{}, uint64) error
}

// WriteTo includes its type number, and can be directly encoded with Writer.
type WriteTo interface {
	WriteTo(Writer) error
}

type writer struct {
	io.Writer
	b []byte
}

// NewWriter creates a new buffered Writer.
func NewWriter(w io.Writer) Writer {
	return &writer{
		Writer: w,
		b:      make([]byte, MaxSize),
	}
}

func (w *writer) Write(v interface{}, t uint64) error {
	n, err := writeTLV(w.b, t, reflect.ValueOf(v), false)
	if err != nil {
		return err
	}
	_, err = w.Writer.Write(w.b[:n])
	return err
}

func writeVarNum(b []byte, v uint64) int {
	switch {
	case v > math.MaxUint32:
		b[0] = 0xFF
		binary.BigEndian.PutUint64(b[1:], v)
		return 9
	case v > math.MaxUint16:
		b[0] = 0xFE
		binary.BigEndian.PutUint32(b[1:], uint32(v))
		return 5
	case v > math.MaxUint8-3:
		b[0] = 0xFD
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		return 3
	default:
		b[0] = uint8(v)
		return 1
	}
}

func writeUint64(b []byte, v uint64) int {
	switch {
	case v > math.MaxUint32:
		b[0] = 8
		binary.BigEndian.PutUint64(b[1:], v)
		return 9
	case v > math.MaxUint16:
		b[0] = 4
		binary.BigEndian.PutUint32(b[1:], uint32(v))
		return 5
	case v > math.MaxUint8:
		b[0] = 2
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		return 3
	default:
		b[0] = 1
		b[1] = uint8(v)
		return 2
	}
}

func writeStruct(b []byte, structValue reflect.Value, noSignature bool) (n int, err error) {
	err = walkStruct(structValue.Type(), func(tag *structTag, i int) error {
		fieldValue := structValue.Field(i)
		if tag.Signature && noSignature ||
			tag.Optional && isZero(fieldValue) {
			return nil
		}
		nn, err := writeTLV(b[n:], tag.Type, fieldValue, noSignature)
		if err != nil {
			return err
		}
		n += nn
		return nil
	})
	return
}

var (
	typeBinaryMarshaler = reflect.TypeOf((*encoding.BinaryMarshaler)(nil)).Elem()
)

func writeTLV(b []byte, t uint64, value reflect.Value, noSignature bool) (n int, err error) {
	if value.Type().Implements(typeBinaryMarshaler) {
		var v []byte
		v, err = value.Interface().(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			return
		}
		n += writeVarNum(b[n:], t)
		n += writeVarNum(b[n:], uint64(len(v)))
		n += copy(b[n:], v)
		return
	}
	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			n += writeVarNum(b[n:], t)
			b[n] = 0
			n++
		}
	case reflect.Uint64:
		n += writeVarNum(b[n:], t)
		n += writeUint64(b[n:], value.Uint())
	case reflect.Slice:
		switch value.Type().Elem().Kind() {
		case reflect.Uint8:
			n += writeVarNum(b[n:], t)
			v := value.Bytes()
			n += writeVarNum(b[n:], uint64(len(v)))
			n += copy(b[n:], v)
		default:
			var nn int
			for j := 0; j < value.Len(); j++ {
				nn, err = writeTLV(b[n:], t, value.Index(j), noSignature)
				if err != nil {
					return
				}
				n += nn
			}
		}
	case reflect.String:
		n += writeVarNum(b[n:], t)
		v := value.String()
		n += writeVarNum(b[n:], uint64(len(v)))
		n += copy(b[n:], v)
	case reflect.Ptr:
		return writeTLV(b[n:], t, value.Elem(), noSignature)
	case reflect.Struct:
		n += writeVarNum(b[n:], t)
		v := b[n+9:]
		var nn int
		nn, err = writeStruct(v, value, noSignature)
		if err != nil {
			return
		}
		n += writeVarNum(b[n:], uint64(nn))
		n += copy(b[n:], v[:nn])
	default:
		err = ErrNotSupported
	}
	return
}
