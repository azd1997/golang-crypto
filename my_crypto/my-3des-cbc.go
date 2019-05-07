package my_crypto

import (
	"crypto/cipher"
	"crypto/des"
)

//3des对称加密
func Encrypt3DES(src, key []byte) []byte {
	//创建并返回一个使用DES算法的cipher.Block接口
	block, err := des.NewTripleDESCipher(key)
	HandleError(err)
	//对最后一个明文分组进行数据填充
	src = paddingText(src, block.BlockSize())
	//创建一个密码分组为连接模式的，底层采用DES加密的BlockMode接口
	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	//加密连续的数据块
	blockMode.CryptBlocks(src, src)

	return src
}

//3des解密
func Decrypt3DES(src, key []byte) []byte {

	block, err := des.NewTripleDESCipher(key)
	HandleError(err)

	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])

	blockMode.CryptBlocks(src, src) //解密结果覆盖原内容

	src = deletePaddingText(src)

	return src
}
