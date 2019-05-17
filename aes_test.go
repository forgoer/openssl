package openssl

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/base64"
)

func TestAes(t *testing.T) {
	src := []byte("1234567890_QWERTY")
	key := []byte("12345123451234512345123451234512")
	dst, err := AesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)

	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "MdzAshBM1s7uxcblqWIyTY0s2tcEpGg+OwaQzHMd45o=")

}

func TestAesEncrypt(t *testing.T) {
	src := []byte("123456")

	// AES-128-ECB, PKCS7_PADDING
	key := []byte("1234512345123451")
	dst, err := AesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "SpfAShHImQhWjd/21Pgz2Q==")

	// AES-192-ECB, PKCS7_PADDING
	key = []byte("123451234512345123451234")
	dst, err = AesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "vOwA1oZknZ54rgXETVYwMg==")

	// AES-256-ECB, PKCS7_PADDING
	key = []byte("12345123451234512345123451234512")
	dst, err = AesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "F+tlXjWffI4xt656KVwgLg==")
}

func TestAesECBDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("SpfAShHImQhWjd/21Pgz2Q==")
	assert.NoError(t, err)

	// AES-128-ECB, PKCS7_PADDING
	key := []byte("1234512345123451")
	dst, err := AesECBDecrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))

	// AES-192-ECB, PKCS7_PADDING
	src, _ = base64.StdEncoding.DecodeString("vOwA1oZknZ54rgXETVYwMg==")
	key = []byte("123451234512345123451234")
	dst, err = AesECBDecrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))

	// AES-256-ECB, PKCS7_PADDING
	src, _ = base64.StdEncoding.DecodeString("F+tlXjWffI4xt656KVwgLg==")
	key = []byte("12345123451234512345123451234512")
	dst, err = AesECBDecrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}

func TestAesCBCEncrypt(t *testing.T) {
	src := []byte("123456")
	iv := []byte("6789067890678906")
	// AES-128-ECB, PKCS7_PADDING
	key := []byte("1234512345123451")
	dst, err := AesCBCEncrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "0huM2ppRyYZmZnzdoCL/tA==")
}

func TestAesCBCDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("0huM2ppRyYZmZnzdoCL/tA==")
	assert.NoError(t, err)

	iv := []byte("6789067890678906")

	// AES-128-ECB, PKCS7_PADDING
	key := []byte("1234512345123451")
	dst, err := AesCBCDecrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}