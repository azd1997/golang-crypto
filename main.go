package main

import "github.com/azd1997/golang-crypto/my_crypto"

//main.go用来测试各个加密算法

func main() {
	//my_crypto.DesTest2("天真烂漫")
	//my_crypto.TripleDesTest2("无法无天")
	//my_crypto.AesTest2("我！")
	//my_crypto.RsaTest()
	my_crypto.GetMD5Test([]byte("天青色等烟雨"))
}
