package desp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/forgoer/openssl"
	"strings"
)

const (
	AlgAesEcb  = "AES-ECB"
	AlgAesCbc  = "AES-CBC"
	AlgDesEcb  = "DES-ECB"
	AlgDesCbc  = "DES-CBC"
	Alg3DesEcb = "3DES-ECB"
	Alg3DesCbc = "3DES-CBC"
)

// 可用的加密算法
var algList = []string{
	AlgAesEcb, AlgAesCbc, AlgDesEcb, AlgDesCbc, Alg3DesEcb, Alg3DesCbc,
}
var algListString = strings.Join(algList, ",")

// Algorithm 加密传输处理
type Algorithm struct {
	Alg string
	Key string
}

func NewAlgorithm(alg, key string) *Algorithm {
	algorithm := &Algorithm{
		Alg: strings.ToUpper(alg),
		Key: key,
	}
	return algorithm
}

// Encode 加密
func (a *Algorithm) Encode(origin string) (string, error) {
	switch a.Alg {
	case AlgAesEcb:
		dst, err := openssl.AesECBEncrypt([]byte(origin), []byte(a.Key), openssl.PKCS7_PADDING)
		if err == nil {
			return base64.StdEncoding.EncodeToString(dst), nil
		}
		return "", err
	case AlgAesCbc:
		iv := []byte(a.Key)
		dst, err := openssl.AesCBCEncrypt([]byte(origin), []byte(a.Key), iv, openssl.PKCS7_PADDING)
		if err == nil {
			return base64.StdEncoding.EncodeToString(dst), nil
		}
		return "", err
	case AlgDesEcb:
		dst, err := openssl.DesECBEncrypt([]byte(origin), []byte(a.Key), openssl.PKCS7_PADDING)
		if err == nil {
			return base64.StdEncoding.EncodeToString(dst), nil
		}
		return "", err
	case AlgDesCbc:
		iv := []byte(a.Key)
		dst, err := openssl.DesCBCEncrypt([]byte(origin), []byte(a.Key), iv, openssl.PKCS7_PADDING)
		if err == nil {
			return base64.StdEncoding.EncodeToString(dst), nil
		}
		return "", err
	case Alg3DesEcb:
		dst, err := openssl.Des3ECBEncrypt([]byte(origin), []byte(a.Key), openssl.PKCS7_PADDING)
		if err == nil {
			return base64.StdEncoding.EncodeToString(dst), nil
		}
		return "", err
	case Alg3DesCbc:
		iv := []byte(a.Key)
		dst, err := openssl.Des3CBCEncrypt([]byte(origin), []byte(a.Key), iv, openssl.PKCS7_PADDING)
		if err == nil {
			return base64.StdEncoding.EncodeToString(dst), nil
		}
		return "", err
	default:
		return "", errors.New(fmt.Sprintf("加密失败，算法%v暂不不支持, 参考：%v", a.Alg, algListString))
	}
}

// Decode 解密
func (a *Algorithm) Decode(cipher string) (string, error) {
	switch a.Alg {
	case AlgAesEcb:
		by, er := base64.StdEncoding.DecodeString(cipher)
		if er != nil {
			return "", errors.New(fmt.Sprintf("密文进行 base64 提取错误\n  %v", er))
		}
		dst, err := openssl.AesECBDecrypt(by, []byte(a.Key), openssl.PKCS7_PADDING)
		if err == nil {
			return string(dst), nil
		}
		return "", err
	case AlgAesCbc:
		by, er := base64.StdEncoding.DecodeString(cipher)
		if er != nil {
			return "", errors.New(fmt.Sprintf("密文进行 base64 提取错误\n  %v", er))
		}
		iv := []byte(a.Key)
		dst, err := openssl.AesCBCDecrypt(by, []byte(a.Key), iv, openssl.PKCS7_PADDING)
		if err == nil {
			return string(dst), nil
		}
		return "", err
	case AlgDesEcb:
		by, er := base64.StdEncoding.DecodeString(cipher)
		if er != nil {
			return "", errors.New(fmt.Sprintf("密文进行 base64 提取错误\n  %v", er))
		}
		dst, err := openssl.DesECBDecrypt(by, []byte(a.Key), openssl.PKCS7_PADDING)
		if err == nil {
			return string(dst), nil
		}
		return "", err
	case AlgDesCbc:
		by, er := base64.StdEncoding.DecodeString(cipher)
		if er != nil {
			return "", errors.New(fmt.Sprintf("密文进行 base64 提取错误\n  %v", er))
		}
		iv := []byte(a.Key)
		dst, err := openssl.DesCBCDecrypt(by, []byte(a.Key), iv, openssl.PKCS7_PADDING)
		if err == nil {
			return string(dst), nil
		}
		return "", err
	case Alg3DesEcb:
		by, er := base64.StdEncoding.DecodeString(cipher)
		if er != nil {
			return "", errors.New(fmt.Sprintf("密文进行 base64 提取错误\n  %v", er))
		}
		dst, err := openssl.Des3ECBDecrypt(by, []byte(a.Key), openssl.PKCS7_PADDING)
		if err == nil {
			return string(dst), nil
		}
		return "", err
	case Alg3DesCbc:
		by, er := base64.StdEncoding.DecodeString(cipher)
		if er != nil {
			return "", errors.New(fmt.Sprintf("密文进行 base64 提取错误\n  %v", er))
		}
		iv := []byte(a.Key)
		dst, err := openssl.Des3CBCDecrypt(by, []byte(a.Key), iv, openssl.PKCS7_PADDING)
		if err == nil {
			return string(dst), nil
		}
		return "", err
	default:
		return "", errors.New(fmt.Sprintf("解密失败，算法%v暂不不支持, 参考：%v", a.Alg, algListString))
	}
}

// AlgList 获取可用导入加密算法
func AlgList() []string {
	return algList
}
