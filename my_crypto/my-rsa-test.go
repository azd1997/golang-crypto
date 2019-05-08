package my_crypto

import "fmt"

func RsaGenKeyTest() {
	err := RsaGenKey(128)
	fmt.Println("错误信息：", err)
}
