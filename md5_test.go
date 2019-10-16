package openssl

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMd5(t *testing.T) {
	src := "apple"
	dst := Md5(src)
	assert.Equal(t, dst, "1f3870be274f6c49b3e31a0c6728957f")

	dst = Md5(src, true)
	assert.Equal(t, dst, "274f6c49b3e31a0c")
}
