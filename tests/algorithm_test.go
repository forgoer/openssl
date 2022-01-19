package desp

import (
	"gitee.com/conero/uymas/str"
	"testing"
)

func TestAlgorithm_Encode_all(t *testing.T) {
	// 随机密文
	key := str.RandStr.SafeStr(32)
	origin := str.RandStr.SafeStr(500) + "中华人民共和国-贵州.贵阳"

	for _, algStr := range algList {
		alg := NewAlgorithm(algStr, key)
		cp, err := alg.Encode(origin)
		if err != nil {
			t.Errorf("算法 %v 加密错误，%v", algStr, err)
		}

		// 解密参照
		refOrigin, er := alg.Decode(cp)
		if er != nil {
			t.Errorf("算法 %v 解密错误，%v", algStr, err)
		}

		if refOrigin != origin {
			t.Errorf("算法 %v 加解密错误，\n 秘钥 %v", algStr, key)
		}

		// 成功显示
		t.Logf("√ => 算法 %v 通过测试，加解密无误", algStr)
	}
}
