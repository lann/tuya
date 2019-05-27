package net

import (
	"bytes"
	"testing"
)

var (
	testKey        = []byte("bbe88b3f4106d354")
	testPlaintext  = []byte(`{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}`)
	testCiphertext = []byte("3.133ed3d4a21effe90zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=")
)

func TestEncrypt(t *testing.T) {
	c, err := NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := c.Encrypt(testPlaintext)
	if !bytes.Equal(ciphertext, testCiphertext) {
		t.Errorf("got:\n%s\nwant:\n%s", ciphertext, testCiphertext)
	}
}

func TestDecrypt(t *testing.T) {
	c, err := NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := c.Decrypt(testCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, testPlaintext) {
		t.Errorf("got:\n%q\nwant:\n%q", plaintext, testPlaintext)
	}
}

func TestDecryptBadMAC(t *testing.T) {
	c, err := NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	badCiphertext := append([]byte{}, testCiphertext...)
	badCiphertext[10] = 'f'
	_, err = c.Decrypt(badCiphertext)
	if err != ErrTagVerification {
		t.Errorf("got %v want %v", err, ErrTagVerification)
	}
}

func TestMAC(t *testing.T) {
	tag := testCiphertext[3:19]
	expectedTag := macTag(nil, testKey, testCiphertext[19:])
	if !bytes.Equal(tag, expectedTag) {
		t.Errorf("%s != %s", tag, expectedTag)
	}
}
