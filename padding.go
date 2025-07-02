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

var paddingFunctions = map[string]func([]byte, int) []byte{
	PKCS5_PADDING: PKCS5Padding,
	PKCS7_PADDING: PKCS7Padding,
	ZEROS_PADDING: ZerosPadding,
}

var unpaddingFunctions = map[string]func([]byte) ([]byte, error){
	PKCS5_PADDING: PKCS5Unpadding,
	PKCS7_PADDING: PKCS7UnPadding,
	ZEROS_PADDING: ZerosUnPadding,
}

// Applies the specified padding scheme to the input data.
func Padding(padding string, src []byte, blockSize int) []byte {
	if fn, ok := paddingFunctions[padding]; ok {
		return fn(src, blockSize)
	}
	return src
}

// Removes the specified padding from the input data.
func UnPadding(padding string, src []byte) ([]byte, error) {
	if fn, ok := unpaddingFunctions[padding]; ok {
		return fn(src)
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
	length := len(src)
	if length == 0 {
		return src, nil
	}
	for i := length - 1; i >= 0; i-- {
		if src[i] != 0 {
			return src[:i+1], nil
		}
	}
	return []byte{}, nil
}
