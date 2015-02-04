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
	return &reader{r: bufio.NewReader(r)}
}

type reader struct {
	r *bufio.Reader
	t uint64
}

func (this *reader) Peek() uint64 {
	if this.t == 0 {
		b, _ := this.r.Peek(9)
		this.t, _ = readVarNum(bytes.NewReader(b))
	}
	return this.t
}

func (this *reader) Read(b []byte) (int, error) {
	this.t = 0
	return this.r.Read(b)
}
