package my_crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

//Go原生只支持16B（128bit）AES密钥

func EncryptAES(src, key []byte) []byte {

	block, err := aes.NewCipher(key)
	HandleError(err)

	src = paddingText(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key) //key作为初始向量

	blockMode.CryptBlocks(src, src)

	return src
}

func DecryptAES(src, key []byte) []byte {
	block, err := aes.NewCipher(key)
	HandleError(err)

	blockMode := cipher.NewCBCDecrypter(block, key) //key作为初始向量

	blockMode.CryptBlocks(src, src)

	src = deletePaddingText(src)

	return src
}
