package openssl

import (
	"crypto/cipher"
)

func ECBEncrypt(block cipher.Block, src, key []byte, padding string) ([]byte, error) {
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

func ECBDecrypt(block cipher.Block, src, key []byte, padding string) ([]byte, error) {
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
