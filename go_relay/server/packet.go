package server

import (
	"encoding/binary"
	"io"
)

// PacketHeader represents the binary header from the C++ producer.
// 30 bytes packed.
type PacketHeader struct {
	Timestamp   uint64   // 8 bytes
	ProviderId  [16]byte // 16 bytes
	EventId     uint16   // 2 bytes
	PayloadSize uint32   // 4 bytes
}

const HeaderSize = 30

// ReadHeader reads the 30-byte header from the reader.
func ReadHeader(r io.Reader) (*PacketHeader, error) {
	buf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	h := &PacketHeader{}
	h.Timestamp = binary.LittleEndian.Uint64(buf[0:8])
	copy(h.ProviderId[:], buf[8:24])
	h.EventId = binary.LittleEndian.Uint16(buf[24:26])
	h.PayloadSize = binary.LittleEndian.Uint32(buf[26:30])

	return h, nil
}
