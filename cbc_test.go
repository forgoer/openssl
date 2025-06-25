package openssl

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCBCEncryptAndDecrypt(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes for AES-256
	block, err := aes.NewCipher(key)
	assert.NoError(t, err)

	src := []byte("test data")
	iv := []byte("1234567890123456") // 16 bytes for AES

	// Test encryption
	encrypted, err := CBCEncrypt(block, src, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Test decryption
	decrypted, err := CBCDecrypt(block, encrypted, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestCBCIVPending(t *testing.T) {
	blockSize := 16
	testCases := []struct {
		iv       []byte
		expected []byte
	}{
		{[]byte("1234"), append([]byte("1234"), bytes.Repeat([]byte{0}, 12)...)},
		{[]byte("12345678901234567890"), []byte("1234567890123456")},
		{[]byte("1234567890123456"), []byte("1234567890123456")},
	}

	for _, tc := range testCases {
		result := cbcIVPending(tc.iv, blockSize)
		assert.Equal(t, tc.expected, result)
	}
}
