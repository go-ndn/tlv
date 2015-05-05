package tlv

import (
	"bytes"
	"io"
	"net"
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

// The max size for tlv is 8800.
//
// 1. One "common" size of Ethernet jumbo packets is 9000 octets
// 2. It is generally sufficient to carry an 8192 byte payload in a content object
// 3. 8800 bytes was a message size limit in ONC-RPC over UDP
// 4. Some OSs have a limited default UDP packet size (MacOS: net.inet.udp.maxdgram: 9216) and/or a limited space for receive buffers (MacOS: net.inet.udp.recvspace: 42080)
// 5. When a ContentObject is signed it is not known whether the transmission path will be UDP / TCP / ..
const (
	MaxSize = 8800
)

func readPacketTLV(r io.Reader) (uint64, []byte, error) {
	if _, ok := r.(net.PacketConn); ok {
		b := make([]byte, MaxSize)
		n, _ := r.Read(b)
		return readTLV(bytes.NewReader(b[:n]))
	}
	return readTLV(r)
}

func (r *reader) Peek() uint64 {
	if r.t == 0 {
		t, v, err := readPacketTLV(r.rd)
		if err == nil {
			r.t, r.v = t, v
		}
	}
	return r.t
}

func (r *reader) Read() (uint64, []byte, error) {
	if r.t == 0 {
		return readPacketTLV(r.rd)
	}
	t, v := r.t, r.v
	r.t, r.v = 0, nil
	return t, v, nil
}
