package openssl

import (
	"crypto/sha1"
	"encoding/hex"
)

// Sha1 Calculate the sha1 hash of a string
func Sha1(str string) string {
	h := sha1.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}
