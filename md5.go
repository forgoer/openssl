package openssl

import (
	"crypto/md5"
	"encoding/hex"
)

// Md5 Calculate the md5 hash of a string
// If the optional rawOutput is set to true, then the md5 digest is instead returned in raw binary format with a length of 16.
func Md5(str string, rawOutput ...bool) string {
	h := md5.New()
	h.Write([]byte(str))
	str = hex.EncodeToString(h.Sum(nil))
	if len(rawOutput) > 0 && rawOutput[0] {
		str = str[8:24]
	}

	return str
}
