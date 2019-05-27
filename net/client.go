package net

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
)

// ErrNoKey is returned when a cryptographic operation is required but no key
// was specified in ClientConfig.
var ErrNoKey = errors.New("no Key in ClientConfig")

// A ClientConfig holds configuration for a Client connection. It may be reused
// for multiple connections.
type ClientConfig struct {
	// Addr is the address of the device to connect to.
	Addr string

	// Key is the cryptographic key used to en/decrypt messages.
	// Note that while keys may appear to be hex encoded, they are actually raw
	// bytes that happen to only use hex characters.
	Key string
}

// Dial connects to a device using the ClientConfig.
func (cc ClientConfig) Dial() (*Client, error) {
	var cipher *Cipher
	if cc.Key != "" {
		var err error
		cipher, err = NewCipher([]byte(cc.Key))
		if err != nil {
			return nil, fmt.Errorf("NewCipher: %v", err)
		}
	}

	conn, err := net.Dial("tcp", cc.Addr)
	if err != nil {
		return nil, fmt.Errorf("Dial: %v", err)
	}

	return &Client{
		conn:   conn,
		cipher: cipher,
	}, nil
}

// A Client is a Tuya device client. Its lifetime is tied to an underlying TCP
// connection; once that connection is closed the Client may no longer be used.
type Client struct {
	conn   net.Conn
	cipher *Cipher

	// Incremented for each message; reply messages match a request seq number.
	seq uint32

	// Protects `conn` and `seq` from multiple writers.
	sync.Mutex
}

// Close closes the Client connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Write sends a message to the connected device. The message is constructed
// from the `cmd` number and `payload`, which may be a JSON-serializable
// object or a []byte containing a raw message. If `encrypt` is true, the
// message will be encrypted. Write may be called from multiple goroutines.
func (c *Client) Write(cmd uint32, encrypt bool, payload interface{}) (seq uint32, err error) {
	if encrypt && c.cipher == nil {
		return 0, ErrNoKey
	}

	// Marshal JSON (if necessary)
	data, isBytes := payload.([]byte)
	if !isBytes {
		var err error
		data, err = json.Marshal(payload)
		if err != nil {
			return 0, fmt.Errorf("payload Marshal: %v", err)
		}
	}

	// Encrypt payload (if requested)
	if encrypt {
		data = c.cipher.Encrypt(data)
	}

	// Write frame
	c.Lock()
	defer c.Unlock()
	c.seq += 1
	frame := &Frame{
		Seq:     c.seq,
		Cmd:     cmd,
		Payload: data,
	}
	if err := frame.Encode(c.conn); err != nil {
		return 0, fmt.Errorf("frame Encode: %v", err)
	}
	return c.seq, nil
}

// Read reads a Response from the connected device; it will block until it reads
// a full message or encounters invalid message data. It is *not* safe to call
// from multiple goroutines.
func (c *Client) Read() (*Response, error) {
	f, err := DecodeFrame(c.conn)
	if err != nil {
		return nil, fmt.Errorf("DecodeFrame: %v", err)
	}

	// Decrypt, if needed.
	if detectEncryption(f.Payload) {
		plaintext, err := c.cipher.Decrypt(f.Payload)
		if err != nil {
			return nil, fmt.Errorf("Decrypt: %v", err)
		}
		f.Payload = plaintext
	}

	return &Response{f}, nil
}

// A Response represents a partially-decoded message from a device. Consumers
// will typically determine the expected payload based on the Frame `Seq` or
// `Cmd` and then `DecodeJSON` into an appropriate struct.
type Response struct {
	*Frame
}

// Err returns nil for messages with a error code of zero. It returns non-nil
// errors if the message has a non-zero or invalid error code. For non-zero
// error codes it returns a ResponseError.
func (r *Response) Err() error {
	if len(r.Payload) < 4 {
		return fmt.Errorf("payload too short; %d < 4", len(r.Payload))
	}
	if errCode := binary.BigEndian.Uint32(r.Payload); errCode != 0 {
		return ResponseError{
			Code:    errCode,
			Message: string(r.Payload[4:]),
		}
	}
	return nil
}

// Bytes returns the raw payload bytes, without the 4 leading error code bytes.
func (r *Response) Bytes() ([]byte, error) {
	if err := r.Err(); err != nil {
		return nil, err
	}
	return r.Payload[4:], nil
}

// DecodeJSON unmarshals the payload into an object with `json.Unmarshal`.
func (r *Response) DecodeJSON(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("Unmarshal: %v", err)
	}
	return nil
}

// ResponseError is returned by `Response.Err()` for non-zero error codes.
type ResponseError struct {
	Code    uint32
	Message string
}

// Error implements the error interface.
func (re ResponseError) Error() string {
	return fmt.Sprintf("%s [error code %d]", re.Message, re.Code)
}
