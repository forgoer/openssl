package openssl

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRSAEncrypt(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)
	t.Logf("private key: %s\n", priBuf.Bytes())

	pubBuf := bytes.NewBuffer(nil)
	err = RSAGeneratePublicKey(priBuf.Bytes(), pubBuf)
	assert.NoError(t, err)
	t.Logf("public key: %s\n", pubBuf.Bytes())

	src := []byte("123456")
	dst, err := RSAEncrypt(src, pubBuf.Bytes())
	assert.NoError(t, err)
	t.Logf("encrypt out: %s\n", base64.RawStdEncoding.EncodeToString(dst))

	dst, err = RSADecrypt(dst, priBuf.Bytes())
	assert.NoError(t, err)

	assert.Equal(t, src, dst)

	t.Logf("src: %s \ndst:%s", src, dst)
}

func TestRSASign(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)
	t.Logf("private key: %s\n", priBuf.Bytes())

	pubBuf := bytes.NewBuffer(nil)
	err = RSAGeneratePublicKey(priBuf.Bytes(), pubBuf)
	assert.NoError(t, err)
	t.Logf("public key: %s\n", pubBuf.Bytes())

	src := []byte("123456")
	sign, err := RSASign(src, priBuf.Bytes(), crypto.SHA256)
	assert.NoError(t, err)
	t.Logf("sign out: %s\n", base64.RawStdEncoding.EncodeToString(sign))

	err = RSAVerify(src, sign, pubBuf.Bytes(), crypto.SHA256)
	assert.NoError(t, err)
}
