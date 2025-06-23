package openssl

import (
	"bytes"
	"errors"
)

// Error indicating an issue during the unpadding process.
var ErrUnPadding = errors.New("UnPadding error")

const PKCS5_PADDING = "PKCS5"
const PKCS7_PADDING = "PKCS7"
const ZEROS_PADDING = "ZEROS"

// Applies the specified padding scheme to the input data.
func Padding(padding string, src []byte, blockSize int) []byte {
	switch padding {
	case PKCS5_PADDING:
		src = PKCS5Padding(src, blockSize)
	case PKCS7_PADDING:
		src = PKCS7Padding(src, blockSize)
	case ZEROS_PADDING:
		src = ZerosPadding(src, blockSize)
	}
	return src
}

// Removes the specified padding from the input data.
func UnPadding(padding string, src []byte) ([]byte, error) {
	switch padding {
	case PKCS5_PADDING:
		return PKCS5Unpadding(src)
	case PKCS7_PADDING:
		return PKCS7UnPadding(src)
	case ZEROS_PADDING:
		return ZerosUnPadding(src)
	}
	return src, nil
}

// Applies PKCS5 padding to the input data. In practice, it uses PKCS7 padding.
func PKCS5Padding(src []byte, blockSize int) []byte {
	return PKCS7Padding(src, blockSize)
}

// Removes PKCS5 padding from the input data. In practice, it uses PKCS7 unpadding.
func PKCS5Unpadding(src []byte) ([]byte, error) {
	return PKCS7UnPadding(src)
}

// Applies PKCS7 padding to the input data.
func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// Removes PKCS7 padding from the input data.
func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return src, ErrUnPadding
	}
	unpadding := int(src[length-1])
	if length < unpadding {
		return src, ErrUnPadding
	}
	return src[:(length - unpadding)], nil
}

// Applies zero padding to the input data.
func ZerosPadding(src []byte, blockSize int) []byte {
	paddingCount := blockSize - len(src)%blockSize
	if paddingCount == 0 {
		return src
	} else {
		return append(src, bytes.Repeat([]byte{byte(0)}, paddingCount)...)
	}
}

// Removes zero padding from the input data.
func ZerosUnPadding(src []byte) ([]byte, error) {
	for i := len(src) - 1; ; i-- {
		if src[i] != 0 {
			return src[:i+1], nil
		}
	}
}
