package openssl

import (
	"crypto/aes"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestECBEncryptAndDecrypt(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes for AES-256
	block, err := aes.NewCipher(key)
	assert.NoError(t, err)

	src := []byte("test data")

	// Test encryption
	encrypted, err := ECBEncrypt(block, src, PKCS7_PADDING)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Test decryption
	decrypted, err := ECBDecrypt(block, encrypted, PKCS7_PADDING)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestECBEncrypterCryptBlocks(t *testing.T) {
	key := []byte("1234567890123456") // 16 bytes for AES-128
	block, err := aes.NewCipher(key)
	assert.NoError(t, err)

	encrypter := NewECBEncrypter(block)
	src := make([]byte, encrypter.BlockSize()*2)
	dst := make([]byte, len(src))

	encrypter.CryptBlocks(dst, src)
	assert.Equal(t, len(src), len(dst))
}

func TestECBDecrypterCryptBlocks(t *testing.T) {
	key := []byte("1234567890123456") // 16 bytes for AES-128
	block, err := aes.NewCipher(key)
	assert.NoError(t, err)

	decrypter := NewECBDecrypter(block)
	src := make([]byte, decrypter.BlockSize()*2)
	dst := make([]byte, len(src))

	decrypter.CryptBlocks(dst, src)
	assert.Equal(t, len(src), len(dst))
}