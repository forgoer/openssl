package openssl

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/base64"
)

func TestDesEncrypt(t *testing.T) {
	src := []byte("123456")

	// DES-ECB, PKCS7_PADDING
	key := []byte("12345123")
	dst, err := DesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "RJK5Sd4AS44=")
}

func TestDesECBDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("RJK5Sd4AS44=")
	assert.NoError(t, err)

	// DES-ECB, PKCS7_PADDING
	key := []byte("12345123")
	dst, err := DesECBDecrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}

func TestDesCBCEncrypt(t *testing.T) {
	src := []byte("123456")
	iv := []byte("67890678")
	// DES-ECB, PKCS7_PADDING
	key := []byte("12345123")
	dst, err := DesCBCEncrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "fPHNaq8PdWA=")
}

func TestDesCBCDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("fPHNaq8PdWA=")
	assert.NoError(t, err)

	iv := []byte("67890678")

	// DES-ECB, PKCS7_PADDING
	key := []byte("12345123")
	dst, err := DesCBCDecrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}