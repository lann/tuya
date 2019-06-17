package device

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lann/tuya/net"
)

// ErrClosed is return if the Manager has been closed.
var ErrClosed = errors.New("closed")

// A State holds device state ("dps") data.
type State map[uint32]interface{}

// Wrap response and error to pass through responseChan.
type response struct {
	*net.Response
	readErr error
}

type responseChan chan response

// A Manager handles request/response transactions with a device.
type Manager struct {
	devID  string
	client *net.Client

	responseChans map[uint32]responseChan
	sync.Mutex
	closed  bool
	readErr error
}

// NewManager creates a Manager for the given device ID and already-connected Client.
func NewManager(deviceID string, client *net.Client) *Manager {
	m := &Manager{
		devID:         deviceID,
		client:        client,
		responseChans: make(map[uint32]responseChan),
	}
	m.start()
	return m
}

// Close closes the Manager.
func (m *Manager) Close() error {
	m.Lock()
	defer m.Unlock()
	m.closed = true
	if m.readErr == nil {
		m.readErr = ErrClosed
	}
	for seq, respChan := range m.responseChans {
		delete(m.responseChans, seq)
		close(respChan)
	}
	return m.client.Close()
}

// Start a new goroutine for the client read loop.
func (m *Manager) start() {
	go func() {
		defer m.Close()
		for {
			res, err := m.client.Read()
			m.Lock()
			if m.closed {
				break
			}
			if respChan, ok := m.responseChans[res.Seq]; ok {
				respChan <- response{
					Response: res,
					readErr:  err,
				}
				delete(m.responseChans, res.Seq)
			} else {
				log.Printf("no request matching seq %d", res.Seq)
			}
			if err != nil {
				m.readErr = fmt.Errorf("Read: %v", err)
				break
			}
			m.Unlock()
		}
	}()
}

// GetState requests the device state.
func (m *Manager) GetState() (State, error) {
	var res struct {
		State State `json:"dps"`
	}
	err := m.request(0x0a, false, map[string]string{
		"gwId":  m.devID,
		"devId": m.devID,
	}, &res)
	return res.State, err
}

// SetState requests update(s) to the device state.
func (m *Manager) SetState(state State) error {
	return m.request(0x07, true, map[string]interface{}{
		"devId": m.devID,
		"gwId":  m.devID,
		"uid":   "",
		"t":     time.Now().Unix(),
		"dps":   state,
	}, nil)
}

// Manage a request write and a matching blocking response read.
// The request is sent with the given `cmd` number, `req` payload, and
// `encrypt` option (see net.Client.Write).
func (m *Manager) request(cmd uint32, encrypt bool, req, res interface{}) error {
	if m.readErr != nil {
		return m.readErr
	}

	// Write request
	seq, err := m.client.Write(cmd, encrypt, req)
	if err != nil {
		return fmt.Errorf("request Write: %v", err)
	}

	// Register response channel with request seq number
	m.Lock()
	respChan := make(responseChan)
	m.responseChans[seq] = respChan
	m.Unlock()

	// Wait for response.
	// TODO: add timeout (Context?)
	resp := <-respChan
	if resp.readErr != nil {
		return fmt.Errorf("response: %v", err)
	}
	if res == nil {
		return resp.Err()
	}

	// Decode response
	if err := resp.DecodeJSON(res); err != nil {
		return fmt.Errorf("response Decode: %v", err)
	}
	return nil
}
