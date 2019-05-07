package my_crypto

import "fmt"

//测试DES加解密
func DesTest() {
	fmt.Println("===== des 加解密测试")
	src := []byte("少壮不努力，老大徒伤悲！")
	key := []byte("12345678")
	strByteSlice := EncryptDES(src, key)
	strByteSlice = DecryptDES(strByteSlice, key)
	fmt.Println("解密之后的明文：", string(strByteSlice))
}

func DesTest2(str string) {
	fmt.Println("===== des 加解密测试")
	src := []byte(str)
	key := []byte("12345678")
	strByteSlice := EncryptDES(src, key)
	strByteSlice = DecryptDES(strByteSlice, key)
	fmt.Println("解密之后的明文：", string(strByteSlice))
}
