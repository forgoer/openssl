package openssl

import (
	"crypto/des"
)

// DesECBEncrypt
func DesECBEncrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(block, src, key, padding)
}

// DesECBDecrypt
func DesECBDecrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return ECBDecrypt(block, src, key, padding)
}

// DesCBCEncrypt
func DesCBCEncrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCEncrypt(block, src, key, iv, padding)
}

// DesCBCDecrypt
func DesCBCDecrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCDecrypt(block, src, key, iv, padding)
}
