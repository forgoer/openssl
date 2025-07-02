package openssl

import (
	"crypto/sha1"
	"testing"
	"github.com/stretchr/testify/assert"
)

const (
	TestBlockSize10 = 10
	TestBlockSize20 = 20
	TestBlockSize30 = 30
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
	testData := []byte("test")
	result10 := KeyGenerator(testData, TestBlockSize10)
	result20 := KeyGenerator(testData, TestBlockSize20)
	testCases := []struct {
		data      []byte
		blockSize int
		expected  []byte
	}{
		{testData, TestBlockSize10, result10},
		{testData, TestBlockSize20, result20},
		{testData, TestBlockSize30, []byte("test")},
	}

	for _, tc := range testCases {
		result := KeyGenerator(tc.data, tc.blockSize)
		assert.Equal(t, tc.expected, result, "KeyGenerator output should match expected key")
	}
}