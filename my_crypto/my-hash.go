package my_crypto

import (
	"crypto/md5"
	"encoding/hex"
	"io"
)

//Go中哈希函数接口（MD5，SHA-1，SHA256/224/512/384）的使用基本都差不多，此处以MD5为例

//使用Sum方法是一次性对一个数据块进行哈希运算，而使用New接口的方法则可以不断的添加数据，不断计算新的哈希值。
//应用场景不同

func GetMD5withSum(src []byte) string {
	//1.给哈希算法添加数据
	res := md5.Sum(src)
	//数据格式化,下方两种格式化方法都可以
	//myres := fmt.Sprintf("%x", res)
	myRes := hex.EncodeToString(res[:])

	return myRes
}

func GetMD5withNew(src []byte) string {
	//1.创建哈希接口
	hashInterface := md5.New()
	//2.添加数据，可连续多次添加
	_, err := io.WriteString(hashInterface, string(src))
	HandleError(err)
	//_, err = io.WriteString(hashInterface, string(src2))
	//HandleError(err)
	//2.1 添加数据的第二种方法，同样可以连续添加
	hashInterface.Write(src)

	//3.计算结果。hashInterface.Sum(b []byte) 会将原先写入的数据计算哈希hash1，将b计算哈希hash2，再将两个哈希前后拼接
	res := hashInterface.Sum(nil)

	//4.散列值格式化
	myRes := hex.EncodeToString(res)

	return myRes
}
