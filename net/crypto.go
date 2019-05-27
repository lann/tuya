package net

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	supportedVersion = "3.1" // TODO: support other versions?
	tagSize          = 16
)

var (
	ErrPadding         = errors.New("padding error")
	ErrTagVerification = errors.New("tag verification failed")
	ErrTooSmall        = errors.New("ciphertext too small")

	b64     = base64.StdEncoding
	version = []byte(supportedVersion)
)

func detectEncryption(payload []byte) bool {
	// NOTE: This seems to be sufficient in practice, but could be better.
	return bytes.HasPrefix(payload, version)
}

// A Cipher implements Tuya's authenticated encryption cipher.
type Cipher struct {
	key []byte
	aes cipher.Block
}

// NewCipher creates a new Cipher.
func NewCipher(key []byte) (*Cipher, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{key: key, aes: aes}, nil
}

// Encrypt encrypts the given plaintext, which is not modified.
func (c *Cipher) Encrypt(plaintext []byte) []byte {
	blockSize := c.aes.BlockSize()
	padSize := blockSize - (len(plaintext) % blockSize)
	ciphertext := make([]byte, len(plaintext)+padSize)
	copy(ciphertext, plaintext)

	// PKCS#7 padding
	for i := len(plaintext); i < len(ciphertext); i++ {
		ciphertext[i] = byte(padSize)
	}

	// AES ECB
	for i := 0; i < len(ciphertext); i += blockSize {
		c.aes.Encrypt(ciphertext[i:], ciphertext[i:])
	}

	// Output buffer: <version><hex(tag)><base64(ciphertext)>
	outputSize := len(version) + tagSize + b64.EncodedLen(len(ciphertext))
	output := make([]byte, outputSize)
	copy(output, version)

	// Base64 ciphertext
	encoded := output[len(version)+tagSize:]
	b64.Encode(encoded, ciphertext)

	// Tuya MAC
	macTag(output[len(version):], c.key, encoded)

	return output
}

// Decrypt decrypts the given ciphertext, which is not modified.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	blockSize := c.aes.BlockSize()
	if len(ciphertext) < len(version)+tagSize+b64.EncodedLen(blockSize) {
		return nil, ErrTooSmall
	}

	// Version
	if !bytes.HasPrefix(ciphertext, version) {
		return nil, fmt.Errorf("ciphertext doesn't start with %s", version)
	}
	ciphertext = ciphertext[len(version):]

	// Tuya MAC
	tag := ciphertext[:tagSize]
	expectedTag := macTag(nil, c.key, ciphertext[tagSize:])
	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		return nil, ErrTagVerification
	}

	// Base64 data
	b64data := ciphertext[tagSize:]
	plaintext := make([]byte, b64.DecodedLen(len(b64data)))
	n, err := b64.Decode(plaintext, b64data)
	if err != nil {
		return nil, fmt.Errorf("base64 Decode: %v", err)
	}
	plaintext = plaintext[:n]

	// AES ECB
	for i := 0; i < len(plaintext); i += blockSize {
		c.aes.Decrypt(plaintext[i:], plaintext[i:])
	}

	// PKCS#7 padding
	padSize := int(plaintext[len(plaintext)-1])
	if padSize < 1 || padSize > blockSize {
		return nil, ErrPadding
	}
	for i := len(plaintext) - padSize; i < len(plaintext)-1; i++ {
		if plaintext[i] != byte(padSize) {
			return nil, ErrPadding
		}
	}
	return plaintext[:len(plaintext)-padSize], nil
}

func macTag(dst, key, data []byte) []byte {
	// hex(md5("data=" <data> "||lpv=3.1||" <key>)[4:12])
	h := md5.New()
	h.Write([]byte("data="))
	h.Write(data)
	h.Write([]byte("||lpv="))
	h.Write(version)
	h.Write([]byte("||"))
	h.Write(key)
	if dst == nil {
		dst = make([]byte, tagSize)
	}
	hex.Encode(dst, h.Sum(nil)[4:12])
	return dst
}
