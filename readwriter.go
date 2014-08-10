package tlv

import (
	"io"
)

type PeekReader interface {
	Reader
	Peek(n int) ([]byte, error)
}

type Reader interface {
	io.Reader
}

type Writer interface {
	io.Writer
}
