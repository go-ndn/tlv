# tlv

It marshals and unmarshals [go types](https://golang.org/ref/spec#Types) directly to [packet format](http://named-data.net/doc/ndn-tlv/) with [run-time reflection](http://golang.org/pkg/reflect/).

[![GoDoc](https://godoc.org/github.com/go-ndn/tlv?status.svg)](https://godoc.org/github.com/go-ndn/tlv)

## Supported types

- [encoding.BinaryMarshaler and encoding.BinaryUnmarshaler](http://golang.org/pkg/encoding/)
- bool
- uint64
- string
- pointer and slice of any types above
- struct of any types above
