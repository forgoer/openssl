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

func TestPadding(t *testing.T) {
	blockSize := 16
	tests := []struct {
		name    string
		padding string
		src     []byte
		wantLen int
	}{
		{name: "PKCS5", padding: PKCS5_PADDING, src: []byte("test"), wantLen: 16},
		{name: "PKCS7", padding: PKCS7_PADDING, src: []byte("test"), wantLen: 16},
		{name: "Zeros", padding: ZEROS_PADDING, src: []byte("test"), wantLen: 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Padding(tt.padding, tt.src, blockSize)
			assert.Equal(t, tt.wantLen, len(got))
		})
	}
}

func TestUnPadding(t *testing.T) {
	blockSize := 16
	padding := PKCS7_PADDING
	tests := []struct {
		name    string
		src     []byte
		want    []byte
		wantErr bool
	}{
		{name: "valid padding", src: PKCS7Padding([]byte("test"), blockSize), want: []byte("test"), wantErr: false},
		{name: "empty src", src: []byte{}, want: []byte{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnPadding(padding, tt.src)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPKCS5Padding(t *testing.T) {
	blockSize := 16
	tests := []struct {
		name    string
		src     []byte
		wantLen int
	}{
		{name: "test PKCS5", src: []byte("test"), wantLen: 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PKCS5Padding(tt.src, blockSize)
			assert.Equal(t, tt.wantLen, len(got))
		})
	}
}

func TestPKCS5Unpadding(t *testing.T) {
	blockSize := 16
	padded := PKCS5Padding([]byte("test"), blockSize)
	tests := []struct {
		name    string
		src     []byte
		want    []byte
		wantErr bool
	}{
		{name: "valid padding", src: padded, want: []byte("test"), wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PKCS5Unpadding(tt.src)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPKCS7Padding(t *testing.T) {
	blockSize := 16
	tests := []struct {
		name    string
		src     []byte
		wantLen int
	}{
		{name: "test PKCS7", src: []byte("test"), wantLen: 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PKCS7Padding(tt.src, blockSize)
			assert.Equal(t, tt.wantLen, len(got))
		})
	}
}

func TestZerosPadding(t *testing.T) {
	blockSize := 16
	tests := []struct {
		name    string
		src     []byte
		wantLen int
	}{
		{name: "test Zeros", src: []byte("test"), wantLen: 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ZerosPadding(tt.src, blockSize)
			assert.Equal(t, tt.wantLen, len(got))
		})
	}
}

func TestZerosUnPadding(t *testing.T) {
	blockSize := 16
	tests := []struct {
		name string
		src  []byte
		want []byte
	}{
		{name: "test ZerosUnPadding", src: ZerosPadding([]byte("test"), blockSize), want: []byte("test")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ZerosUnPadding(tt.src)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
