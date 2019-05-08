package my_crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

//密文 = 明文^E mod N  (RSA加密)		//E和N的组合就对应着公钥
//明文 = 密文^D mod N  (RSA解密)		//D和N的组合就对应着私钥

func RsaGenKey(bitsLen int) error {

	//1.使用rsa包中的GenerateKey方法生成私钥
	//rand.Reader得到全局随机数，只要是GO语言的项目就可以用
	privateKey, err := rsa.GenerateKey(rand.Reader, bitsLen)
	HandleError(err)

	//2.通过x509标准将得到的rsa私钥序列化为ASN.1（抽象语法标记，一种序列化方法）的DER编码字符串
	privateKeyString := x509.MarshalPKCS1PrivateKey(privateKey)
	//3.将私钥字符串设置到pem格式快中
	block := pem.Block{
		Type:  "RSA PrivateKey",
		Bytes: privateKeyString,
	}
	//4.通过pem将设置好的数据进行编码，并写入磁盘文件
	privFile, err := os.Create("private.pem")
	HandleError(err)
	//defer privFile.Close()
	err = pem.Encode(privFile, &block)
	HandleError(err)
	err = privFile.Close()
	HandleError(err)

	//1.从得到的私钥对象中取出公钥
	pubKey := privateKey.PublicKey
	//2.通过x509标准将得到的rsa私钥序列化为ASN.1（抽象语法标记，一种序列化方法）的DER编码字符串
	pubKeyString, err := x509.MarshalPKIXPublicKey(&pubKey)
	HandleError(err)
	//3.将私钥字符串设置到pem格式快中
	block = pem.Block{
		Type:  "RSA PublicKey",
		Bytes: pubKeyString,
	}

	//4.通过pem将设置好的数据进行编码，并写入磁盘文件
	pubFile, err := os.Create("public.pem")
	HandleError(err)
	//defer pubFile.Close()
	err = pem.Encode(pubFile, &block)
	HandleError(err)
	err = pubFile.Close()
	HandleError(err)

	return nil
}
