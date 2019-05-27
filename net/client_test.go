package net

import (
	"testing"
)

var (
	testJSON    = `{"x": 1}`
	testPayload = []byte("\x00\x00\x00\x00" + testJSON)
)

func TestResponseDecodeJSON(t *testing.T) {
	r := &Response{&Frame{Payload: testPayload}}
	var m map[string]int
	err := r.DecodeJSON(&m)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m["x"] != 1 {
		t.Errorf("bad decode of %s: %v", testJSON, m)
	}
}

func TestResponseError(t *testing.T) {
	r := &Response{&Frame{Payload: []byte("\x00\x00\x00\x01error msg")}}
	err := r.Err()
	if resErr, ok := err.(ResponseError); !ok {
		t.Errorf("Err() %T not a ResponseError", err)
	} else if resErr.Code != 1 {
		t.Errorf("ResponseError.Code %d != 1", resErr.Code)
	} else if resErr.Message != "error msg" {
		t.Errorf("ResponseError.Message '%s' != 'error msg'", resErr.Message)
	}
}
