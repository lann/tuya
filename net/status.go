package net

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
)

const (
	StatusPort = 6666
	ClientPort = 6668
)

// A Status message is read from a UDP broadcast by a device.
type Status struct {
	IP         string `json:"ip"`
	GatewayID  string `json:"gwId"`
	Active     int    `json:"active"`
	Ability    int    `json:"ability"`
	Mode       int    `json:"mode"`
	Encrypt    bool   `json:"encrypt"`
	ProductKey string `json:"productKey"`
	Version    string `json:"version"`
}

// Build a ClientConfig from the Status.
func (s *Status) ClientConfig() ClientConfig {
	// TODO: check Version?
	return ClientConfig{
		Addr: fmt.Sprintf("%s:%d", s.IP, ClientPort),
	}
}

// A UDP broadcast listener that decodes Status messages.
type statusListener struct {
	conn net.PacketConn
	buf  []byte
}

// NewStatusListener makes a broadcast status message listener.
func NewStatusListener() (*statusListener, error) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", StatusPort))
	if err != nil {
		return nil, fmt.Errorf("ListenPacket: %v", err)
	}
	buf := make([]byte, maxPacketSize)
	return &statusListener{conn: conn, buf: buf}, nil
}

// Close closes the status listener.
func (l *statusListener) Close() error {
	return l.conn.Close()
}

// ReadStatus blocks on reading UDP broadcast packet and decodes a Status from it.
func (l *statusListener) ReadStatus() (*Status, error) {
	n, _, err := l.conn.ReadFrom(l.buf)
	if err != nil {
		return nil, fmt.Errorf("ReadFrom: %v", err)
	}

	f, err := DecodeFrame(bytes.NewReader(l.buf[:n]))
	if err != nil {
		return nil, fmt.Errorf("DecodeFrame: %v", err)
	}

	if len(f.Payload) < 4 {
		return nil, fmt.Errorf("payload too small; %d < 4", len(f.Payload))
	}
	if returnCode := binary.BigEndian.Uint32(f.Payload); returnCode != 0 {
		return nil, fmt.Errorf("nonzero return code %d", returnCode)
	}

	status := &Status{}
	if err := json.Unmarshal(f.Payload[4:], status); err != nil {
		return nil, fmt.Errorf("Unmarshal: %v", err)
	}
	return status, nil
}
