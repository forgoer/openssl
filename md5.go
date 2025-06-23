package openssl

import (
	"crypto/md5"
	"encoding/hex"
)

// Calculates the MD5 hash of a given string.
func Md5(str string) []byte {
	h := md5.New()
	_, _ = h.Write([]byte(str))
	return h.Sum(nil)
}

// Calculates the MD5 hash of a given string and returns the result as a hexadecimal string.
func Md5ToString(str string) string {
	return hex.EncodeToString(Md5(str))
}
