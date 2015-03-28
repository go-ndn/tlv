package tlv

import (
	"bytes"
	"io"
)

type Reader interface {
	Peek() uint64
	Read() (uint64, []byte, error)
}

type Writer interface {
	io.Writer
}

type ReadFrom interface {
	ReadFrom(Reader) error
}

type WriteTo interface {
	WriteTo(Writer) error
}

func Copy(from WriteTo, to ReadFrom) (err error) {
	buf := new(bytes.Buffer)
	err = from.WriteTo(buf)
	if err != nil {
		return
	}
	err = to.ReadFrom(NewReader(buf))
	return
}

func NewReader(r io.Reader) Reader {
	return &reader{rd: r}
}

type reader struct {
	rd io.Reader

	t uint64
	v []byte
}

func (r *reader) Peek() uint64 {
	if r.t == 0 {
		t, v, err := readTLV(r.rd)
		if err == nil {
			r.t, r.v = t, v
		}
	}
	return r.t
}

func (r *reader) Read() (uint64, []byte, error) {
	if r.t == 0 {
		return readTLV(r.rd)
	}
	t, v := r.t, r.v
	r.t, r.v = 0, nil
	return t, v, nil
}
