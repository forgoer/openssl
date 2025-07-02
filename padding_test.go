package openssl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const TestBlockSize = 16

func runTestCases(t *testing.T, testCases []struct {
	name    string
	args    struct{ src []byte }
	want    []byte
	wantErr error
}, testFunc func([]byte) ([]byte, error)) {
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			result, err := testFunc(tt.args.src)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestPKCS7UnPadding(t *testing.T) {
	type args struct {
		src []byte
	}
	testCases := []struct {
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
	// Convert testCases to match the expected type of runTestCases
	convertedTestCases := make([]struct {
		name    string
		args    struct{ src []byte }
		want    []byte
		wantErr error
	}, len(testCases))
	for i, tc := range testCases {
		convertedTestCases[i] = struct {
			name    string
			args    struct{ src []byte }
			want    []byte
			wantErr error
		}{
			name:    tc.name,
			args:    struct{ src []byte }{src: tc.args.src},
			want:    tc.want,
			wantErr: tc.wantErr,
		}
	}
	runTestCases(t, convertedTestCases, PKCS7UnPadding)
}

func TestPadding(t *testing.T) {
	tests := []struct {
		name    string
		padding string
		src     []byte
		wantLen int
	}{
		{name: "PKCS5", padding: PKCS5_PADDING, src: []byte("test"), wantLen: TestBlockSize},
		{name: "PKCS7", padding: PKCS7_PADDING, src: []byte("test"), wantLen: TestBlockSize},
		{name: "Zeros", padding: ZEROS_PADDING, src: []byte("test"), wantLen: TestBlockSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Padding(tt.padding, tt.src, TestBlockSize)
			assert.Equal(t, tt.wantLen, len(got))
		})
	}
}

func TestUnPadding(t *testing.T) {
	padding := PKCS7_PADDING
	tests := []struct {
		name    string
		src     []byte
		want    []byte
		wantErr bool
	}{
		{name: "valid padding", src: PKCS7Padding([]byte("test"), TestBlockSize), want: []byte("test"), wantErr: false},
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
	tests := []struct {
		name    string
		src     []byte
		wantLen int
	}{
		{name: "test PKCS5", src: []byte("test"), wantLen: TestBlockSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PKCS5Padding(tt.src, TestBlockSize)
			assert.Equal(t, tt.wantLen, len(got))
		})
	}
}

func TestPKCS5Unpadding(t *testing.T) {
	padded := PKCS5Padding([]byte("test"), TestBlockSize)
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
	tests := []struct {
		name    string
		src     []byte
		wantLen int
	}{
		{name: "test PKCS7", src: []byte("test"), wantLen: TestBlockSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PKCS7Padding(tt.src, TestBlockSize)
			assert.Equal(t, tt.wantLen, len(got))
		})
	}
}

func TestZerosPadding(t *testing.T) {
	tests := []struct {
		name    string
		src     []byte
		wantLen int
	}{
		{name: "test Zeros", src: []byte("test"), wantLen: TestBlockSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ZerosPadding(tt.src, TestBlockSize)
			assert.Equal(t, tt.wantLen, len(got))
		})
	}
}

func TestZerosUnPadding(t *testing.T) {
	tests := []struct {
		name string
		src  []byte
		want []byte
	}{
		{name: "test ZerosUnPadding", src: ZerosPadding([]byte("test"), TestBlockSize), want: []byte("test")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ZerosUnPadding(tt.src)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
