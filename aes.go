package openssl

import (
	"crypto/aes"
	"crypto/cipher"
)

// AesECBEncrypt
func AesECBEncrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	src = Padding(padding, src, blockSize)

	encryptData := make([]byte, len(src))
	tmpData := make([]byte, blockSize)

	for index := 0; index < len(src); index += blockSize {
		block.Encrypt(tmpData, src[index:index+blockSize])
		copy(encryptData, tmpData)
	}
	return encryptData, nil
}

// AesECBDecrypt
func AesECBDecrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	blockSize := block.BlockSize()
	tmpData := make([]byte, blockSize)

	for index := 0; index < len(src); index += blockSize {
		block.Decrypt(tmpData, src[index:index+blockSize])
		copy(dst, tmpData)
	}
	dst = UnPadding(padding, dst)

	return dst, nil
}

// AesCBCEncrypt
func AesCBCEncrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	src = Padding(padding, src, blockSize)

	encryptData := make([]byte, len(src))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptData, src)

	return encryptData, nil
}

// AesCBCDecrypt
func AesCBCDecrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, src)

	dst = UnPadding(padding, dst)

	return dst, nil
}
