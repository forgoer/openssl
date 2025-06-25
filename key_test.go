package openssl

import (
	"crypto/sha1"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestSHA1(t *testing.T) {
	testData := []byte("test")
	h := sha1.New()
	_, _ = h.Write(testData)
	expected := h.Sum(nil)
	result := SHA1(testData)
	assert.Equal(t, expected, result, "SHA1 function output should match expected hash")
}

func TestKeyGenerator(t *testing.T) {
	testCases := []struct {
		data      []byte
		blockSize int
		expected  []byte
	}{
		{[]byte("test"), 10, KeyGenerator([]byte("test"), 10)},
		{[]byte("test"), 20, KeyGenerator([]byte("test"), 20)},
		{[]byte("test"), 30, []byte("test")},
	}

	for _, tc := range testCases {
		result := KeyGenerator(tc.data, tc.blockSize)
		assert.Equal(t, tc.expected, result, "KeyGenerator output should match expected key")
	}
}