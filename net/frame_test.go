package net

import (
	"bytes"
	"strings"
	"testing"
)

var testData = []byte{
	0x00, 0x00, 0x55, 0xaa, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9f,
	0x00, 0x00, 0x00, 0x00, 0x7b, 0x22, 0x69, 0x70,
	0x22, 0x3a, 0x22, 0x31, 0x30, 0x2e, 0x31, 0x30,
	0x2e, 0x32, 0x30, 0x30, 0x2e, 0x31, 0x33, 0x32,
	0x22, 0x2c, 0x22, 0x67, 0x77, 0x49, 0x64, 0x22,
	0x3a, 0x22, 0x30, 0x34, 0x38, 0x38, 0x35, 0x30,
	0x34, 0x37, 0x65, 0x63, 0x66, 0x61, 0x62, 0x63,
	0x39, 0x39, 0x38, 0x65, 0x36, 0x61, 0x22, 0x2c,
	0x22, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x22,
	0x3a, 0x32, 0x2c, 0x22, 0x61, 0x62, 0x69, 0x6c,
	0x69, 0x74, 0x79, 0x22, 0x3a, 0x30, 0x2c, 0x22,
	0x6d, 0x6f, 0x64, 0x65, 0x22, 0x3a, 0x30, 0x2c,
	0x22, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x22, 0x3a, 0x74, 0x72, 0x75, 0x65, 0x2c, 0x22,
	0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x4b,
	0x65, 0x79, 0x22, 0x3a, 0x22, 0x6b, 0x65, 0x79,
	0x35, 0x6e, 0x63, 0x6b, 0x34, 0x74, 0x61, 0x76,
	0x79, 0x34, 0x33, 0x6a, 0x70, 0x22, 0x2c, 0x22,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22,
	0x3a, 0x22, 0x33, 0x2e, 0x31, 0x22, 0x7d, 0x5b,
	0xb7, 0x13, 0xb0, 0x00, 0x00, 0xaa, 0x55,
}

func TestDecodeFrame(t *testing.T) {
	r := bytes.NewReader(testData)
	f, err := DecodeFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("seq=%d cmd=%d", f.Seq, f.Cmd)
	if unread := r.Len(); unread > 0 {
		t.Errorf("unread bytes: %d", unread)
	}
}

func TestDecodeFrameBadCRC(t *testing.T) {
	badData := append([]byte{}, testData...)
	badData[len(badData)-5] += 1
	r := bytes.NewReader(badData)
	_, err := DecodeFrame(r)
	if err == nil || !strings.Contains(err.Error(), "crc mismatch") {
		t.Error("didn't get 'crc mismatch' error")
	}
}

func TestFrameDecodePreallocate(t *testing.T) {
	buf := make([]byte, int(testData[15]))
	f := &Frame{Payload: buf}
	r := bytes.NewReader(testData)
	err := f.Decode(r)
	if err != nil {
		t.Fatal(err)
	}
	if &buf[0] != &f.Payload[0] {
		t.Error("didn't use preallocated Payload")
	}
}

func TestFrameEncode(t *testing.T) {
	f := &Frame{Payload: testData[16 : len(testData)-8]}
	var buf bytes.Buffer
	if err := f.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), testData) {
		t.Errorf("got:\n%x\nwant:\n%x", buf.Bytes(), testData)
	}
}
