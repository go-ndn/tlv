package tlv

import (
	"bufio"
	"bytes"
	"io"
)

type Reader interface {
	io.Reader
	Peek() uint64
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

func NewReader(r io.Reader) Reader {
	return &reader{rd: bufio.NewReader(r)}
}

type reader struct {
	rd *bufio.Reader
	t  uint64
}

func (r *reader) Peek() uint64 {
	if r.t == 0 {
		b, _ := r.rd.Peek(9)
		r.t, _ = readVarNum(bytes.NewReader(b))
	}
	return r.t
}

func (r *reader) Read(b []byte) (int, error) {
	r.t = 0
	return r.rd.Read(b)
}
