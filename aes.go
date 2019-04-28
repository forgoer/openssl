package openssl

import (
	"crypto/aes"
)

// AesECBEncrypt
func AesECBEncrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(block, src, key, padding)
}

// AesECBDecrypt
func AesECBDecrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return ECBDecrypt(block, src, key, padding)
}

// AesCBCEncrypt
func AesCBCEncrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCEncrypt(block, src, key, iv, padding)
}

// AesCBCDecrypt
func AesCBCDecrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCDecrypt(block, src, key, iv, padding)
}
