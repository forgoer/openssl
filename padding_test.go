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
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{
			name:    "len(src)==0",
			args:    args{src: []byte{}},
			want:    []byte{},
			wantErr: ErrUnPadding,
		},
		{
			name:    `src=="121"`,
			args:    args{src: []byte{1, 2, 1}},
			want:    []byte{1, 2},
			wantErr: nil,
		},
		{
			name:    `src=="12111"`,
			args:    args{src: []byte{1, 2, 1, 1, 9}},
			want:    []byte{1, 2, 1, 1, 9},
			wantErr: ErrUnPadding,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := PKCS7UnPadding(tt.args.src)
			t.Log(string(result))
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.want, result)
		})
	}
}
