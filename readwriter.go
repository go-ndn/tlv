package tlv

import (
	"io"
)

type PeekReader interface {
	io.Reader
	Peek(n int) ([]byte, error)
}

type Writer interface {
	io.Writer
}

type ReadFrom interface {
	ReadFrom(PeekReader) error
}

type WriteTo interface {
	WriteTo(Writer) error
}
