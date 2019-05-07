package my_crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"log"
)

//des - 一种对称加密算法
//cbc分组链接模式需要初始化向量iv
//iv值任意，但长度需和明文分组长度保持一致
//加解密时iv需一致！因此如果是不同人不同电脑之间加解密，需要协调好初始向量
//一种办法是：直接使用KEY作为初始化向量

//1.填充最后一个分明文分组的函数
//src - 原始数据
//blockSize - 每个明文分组的数据长度
func paddingText(srcData []byte, blockSize int) []byte {
	//求出最后一个分组需要填充多少字节
	paddingLen := blockSize - len(srcData)%blockSize
	//创建新的切片，用来拼接到原始数据后边
	//切片字节数为paddingLen
	paddingText := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	//将创建的新切片连接到原始数据切片
	paddedData := append(srcData, paddingText...)
	//返回连接后的数据
	return paddedData
}

//2.删除末尾填充的字节
func deletePaddingText(paddedData []byte) []byte {
	//求出要处理的切片长度
	lenToDelete := len(paddedData)
	//去除最后一个字符，得到其整型
	numberToDelete := int(paddedData[lenToDelete-1])
	//将末尾的number个字节删去
	deletedData := paddedData[:lenToDelete-numberToDelete]
	//返回
	return deletedData
}

func HandleError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

/*********************************************************************/

//des对称加密
func EncryptDES(src, key []byte) []byte {
	//创建并返回一个使用DES算法的cipher.Block接口
	block, err := des.NewCipher(key)
	HandleError(err)
	//对最后一个明文分组进行数据填充
	src = paddingText(src, block.BlockSize())
	//创建一个密码分组为连接模式的，底层采用DES加密的BlockMode接口
	iv := []byte("aaaabbbb") //初始化向量
	blockMode := cipher.NewCBCEncrypter(block, iv)
	//加密连续的数据块
	dst := make([]byte, len(src))
	blockMode.CryptBlocks(dst, src)

	return dst
}

//des解密
func DecryptDES(src, key []byte) []byte {

	block, err := des.NewCipher(key)
	HandleError(err)

	iv := []byte("aaaabbbb") //初始化向量，必须和加密时一致
	blockMode := cipher.NewCBCDecrypter(block, iv)

	blockMode.CryptBlocks(src, src) //解密结果覆盖原内容

	data := deletePaddingText(src)

	return data
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
