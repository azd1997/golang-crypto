package my_crypto

import "fmt"

func RsaTest() {
	fmt.Println("====RSA加解密测试")

	err := RsaGenKey(4096)
	fmt.Println("错误信息：", err)

	src := []byte("有意思的是")
	data, err := EncryptRSAPubKey(src, "public.pem")
	data, err = DecryptRSAPrivKey(data, "private.pem")
	fmt.Println("解密字符为：", string(data))

}
