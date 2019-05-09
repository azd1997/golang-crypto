package my_crypto

import "fmt"

func GetMD5Test(src []byte) {
	fmt.Println("====哈希函数之MD5测试")

	res := GetMD5withSum(src)
	fmt.Println("使用Sum函数方法：", res)
	res = GetMD5withNew(src)
	fmt.Println("使用New接口方法：", res)
}
