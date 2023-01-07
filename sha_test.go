package openssl

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSha1(t *testing.T) {
	src := "apple"
	dst := Sha1(src)
	assert.Equal(t, dst, []byte{0xd0, 0xbe, 0x2d, 0xc4, 0x21, 0xbe, 0x4f, 0xcd, 0x1, 0x72, 0xe5, 0xaf, 0xce, 0xea, 0x39, 0x70, 0xe2, 0xf3, 0xd9, 0x40})
}

func TestHmacSha1ToString(t *testing.T) {
	src := "apple"
	dst := HmacSha1ToString("secret", src)
	assert.Equal(t, dst, "2651783bdc7367acd2dde6f830ca0b7104368911")
}

func TestSha256(t *testing.T) {
	src := "apple"
	dst := Sha256(src)
	assert.Equal(t, hex.EncodeToString(dst), "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b")
}

func TestHmacSha256ToString(t *testing.T) {
	dst := HmacSha256ToString("secret", "apple")
	assert.Equal(t, dst, "37431003b2d14b6bddb9334c7ec2ff0ea0c65f96ec650952384e56cae83c398f")
}
