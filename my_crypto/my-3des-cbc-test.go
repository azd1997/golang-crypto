package my_crypto

import "fmt"

//测试DES加解密
func TripleDesTest() {
	fmt.Println("===== 3des 加解密测试")
	src := []byte("少壮不努力，老大徒伤悲！")
	key := []byte("abcdefgh0000111112345678")
	strByteSlice := Encrypt3DES(src, key)
	strByteSlice = Decrypt3DES(strByteSlice, key)
	fmt.Println("解密之后的明文：", string(strByteSlice))
}

func TripleDesTest2(str string) {
	fmt.Println("===== 3des 加解密测试")
	src := []byte(str)
	key := []byte("abcdefgh0000111112345678")
	strByteSlice := Encrypt3DES(src, key)
	strByteSlice = Decrypt3DES(strByteSlice, key)
	fmt.Println("解密之后的明文：", string(strByteSlice))
}
