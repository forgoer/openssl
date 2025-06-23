package openssl

import (
	"crypto/sha1"
)

// Generates a key based on the input data and specified block size.
func KeyGenerator(src []byte, blockSize int) []byte {
	hashs := SHA1(SHA1(src))
	maxLen := len(hashs)
	if blockSize > maxLen {
		return src
	}

	return hashs[0:blockSize]
}

// Computes the SHA-1 hash of the input data.
func SHA1(data []byte) []byte {
	h := sha1.New()
	_, _ = h.Write(data)
	return h.Sum(nil)
}
