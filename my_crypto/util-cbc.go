package my_crypto

import (
	"bytes"
	"log"
)

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
