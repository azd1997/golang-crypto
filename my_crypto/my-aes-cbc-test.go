package my_crypto

import "fmt"

//测试DES加解密
func AesTest() {
	fmt.Println("===== des 加解密测试")
	src := []byte("少壮不努力，老大徒伤悲！")
	key := []byte("1234567812345678")
	strByteSlice := EncryptAES(src, key)
	strByteSlice = DecryptAES(strByteSlice, key)
	fmt.Println("解密之后的明文：", string(strByteSlice))
}

func AesTest2(str string) {
	fmt.Println("===== des 加解密测试")
	src := []byte(str)
	key := []byte("1234567812345678")
	strByteSlice := EncryptAES(src, key)
	strByteSlice = DecryptAES(strByteSlice, key)
	fmt.Println("解密之后的明文：", string(strByteSlice))
}
