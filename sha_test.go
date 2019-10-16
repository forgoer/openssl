package openssl

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSha1(t *testing.T) {
	src := "apple"
	dst := Sha1(src)
	assert.Equal(t, dst, "d0be2dc421be4fcd0172e5afceea3970e2f3d940")
}
