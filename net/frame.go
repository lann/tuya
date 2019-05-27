package net

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// Magic values that bookend frames.
	prefixValue = 0x55aa
	suffixValue = 0xaa55

	// Packets seem to be limited to a single TCP frame in practice.
	maxPacketSize = 0xffff
)

var (
	// Precompute some useful sizes for decoding.
	headerSize     = binary.Size(header{})
	trailerSize    = binary.Size(trailer{})
	MaxPayloadSize = maxPacketSize - trailerSize
)

// Frame header: "55aa" <prefix> <cmd> <length>
type header struct {
	Prefix uint32
	Seq    uint32
	Cmd    uint32
	Length uint32
}

// Frame trailer: <crc> "aa55"
type trailer struct {
	CRC    uint32
	Suffix uint32
}

// A Frame represents a message frame, with the sequence and command numbers parsed out.
type Frame struct {
	Seq     uint32
	Cmd     uint32
	Payload []byte
}

// DecodeFrame decodes a new Frame from a Reader.
func DecodeFrame(r io.Reader) (*Frame, error) {
	f := &Frame{}
	err := f.Decode(r)
	return f, err
}

// Decode decodes from a Reader into an existing Frame.
func (f *Frame) Decode(r io.Reader) error {
	// Prepare CRC
	crc := crc32.NewIEEE()
	rCRC := io.TeeReader(r, crc)

	// Read header
	var h header
	if err := binary.Read(rCRC, binary.BigEndian, &h); err != nil {
		return fmt.Errorf("header Read: %v", err)
	}
	if h.Prefix != prefixValue {
		return fmt.Errorf("bad prefix %x", h.Prefix)
	}
	f.Seq = h.Seq
	f.Cmd = h.Cmd

	// Try to reuse the existing Payload []byte if it is big enough.
	payloadSize := int(h.Length) - trailerSize
	if cap(f.Payload) < payloadSize {
		if payloadSize > MaxPayloadSize {
			return fmt.Errorf("payload too large; %d > %d",
				payloadSize, MaxPayloadSize)
		}
		f.Payload = make([]byte, payloadSize)
	} else {
		f.Payload = f.Payload[:payloadSize]
	}

	// Read payload
	if _, err := io.ReadFull(rCRC, f.Payload); err != nil {
		return fmt.Errorf("payload Read: %v", err)
	}

	// Read trailer
	var t trailer
	if err := binary.Read(r, binary.BigEndian, &t); err != nil {
		return fmt.Errorf("trailer Read: %v", err)
	}
	if t.Suffix != suffixValue {
		return fmt.Errorf("bad suffix %x", t.Suffix)
	}

	// Validate CRC
	if crc.Sum32() != t.CRC {
		return fmt.Errorf("crc mismatch; %x != %x", crc.Sum32(), t.CRC)
	}

	return nil
}

// Encode writes the Frame to a Writer.
func (f *Frame) Encode(w io.Writer) error {
	buf, err := f.buffer()
	if err != nil {
		return err
	}
	if _, err := buf.WriteTo(w); err != nil {
		return fmt.Errorf("WriteTo: %v", err)
	}
	return nil
}

// Return a Buffer containing a wire serialization of the Frame.
func (f *Frame) buffer() (*bytes.Buffer, error) {
	if len(f.Payload) > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large; %d > %d",
			len(f.Payload), MaxPayloadSize)
	}
	length := len(f.Payload) + trailerSize
	buf := bytes.NewBuffer(make([]byte, 0, headerSize+length))

	// Write header
	binary.Write(buf, binary.BigEndian, header{
		Prefix: prefixValue,
		Seq:    f.Seq,
		Cmd:    f.Cmd,
		Length: uint32(length),
	})

	// Write payload
	buf.Write(f.Payload)

	// Calculate CRC
	crc := crc32.ChecksumIEEE(buf.Bytes())

	// Write trailer
	binary.Write(buf, binary.BigEndian, trailer{
		CRC:    crc,
		Suffix: suffixValue,
	})

	return buf, nil
}
