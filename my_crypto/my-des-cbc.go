package my_crypto

import (
	"crypto/cipher"
	"crypto/des"
)

//des - 一种对称加密算法
//cbc分组链接模式需要初始化向量iv
//iv值任意，但长度需和明文分组长度保持一致
//加解密时iv需一致！因此如果是不同人不同电脑之间加解密，需要协调好初始向量
//一种办法是：直接使用KEY作为初始化向量

/*********************************************************************/

//des对称加密
func EncryptDES(src, key []byte) []byte {
	//创建并返回一个使用DES算法的cipher.Block接口
	block, err := des.NewCipher(key)
	HandleError(err)
	//对最后一个明文分组进行数据填充
	src = paddingText(src, block.BlockSize())
	//创建一个密码分组为连接模式的，底层采用DES加密的BlockMode接口
	//iv := []byte("aaaabbbb") //初始化向量
	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	//加密连续的数据块
	//dst := make([]byte, len(src))
	blockMode.CryptBlocks(src, src)

	return src
}

//des解密
func DecryptDES(src, key []byte) []byte {

	block, err := des.NewCipher(key)
	HandleError(err)

	//iv := []byte("aaaabbbb") //初始化向量，必须和加密时一致
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])

	blockMode.CryptBlocks(src, src) //解密结果覆盖原内容

	src = deletePaddingText(src)

	return src
}

/*********************************************************************/

func EncryptDES_keyForIv(src, key []byte) []byte {
	//创建并返回一个使用DES算法的cipher.Block接口
	block, err := des.NewCipher(key)
	HandleError(err)
	//对最后一个明文分组进行数据填充
	src = paddingText(src, block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block, key)
	//加密连续的数据块
	dst := make([]byte, len(src))
	blockMode.CryptBlocks(dst, src)

	return dst
}

func DecryptDES_keyForIv(src, key []byte) []byte {

	block, err := des.NewCipher(key)
	HandleError(err)

	blockMode := cipher.NewCBCDecrypter(block, key)

	blockMode.CryptBlocks(src, src) //解密结果覆盖原内容

	data := deletePaddingText(src)

	return data
}

/*********************************************************************/

func EncryptDES_iv(src, key, iv []byte) []byte {
	//创建并返回一个使用DES算法的cipher.Block接口
	block, err := des.NewCipher(key)
	HandleError(err)
	//对最后一个明文分组进行数据填充
	src = paddingText(src, block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block, iv)
	//加密连续的数据块
	dst := make([]byte, len(src))
	blockMode.CryptBlocks(dst, src)

	return dst
}

func DecryptDES_iv(src, key, iv []byte) []byte {

	block, err := des.NewCipher(key)
	HandleError(err)

	blockMode := cipher.NewCBCDecrypter(block, iv)

	blockMode.CryptBlocks(src, src) //解密结果覆盖原内容

	data := deletePaddingText(src)

	return data
}
