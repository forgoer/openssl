package openssl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPKCS7UnPadding(t *testing.T) {
	type args struct {
		src []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "len(src)==0",
			args: args{src: []byte{}},
			want: []byte{},
		},
		{
			name: `src=="120"`,
			args: args{src: []byte{1, 2, 1}},
			want: []byte{1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, PKCS7UnPadding(tt.args.src), tt.want)
		})
	}
}
