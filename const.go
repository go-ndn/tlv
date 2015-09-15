package tlv

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
