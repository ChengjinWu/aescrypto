package aescrypto

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func Test_Cbc(t *testing.T) {
	/*
	*src 要加密的字符串
	*key 用来加密的密钥 密钥长度可以是128bit、192bit、256bit中的任意一个
	*16位key对应128bit
	 */
	src := "10001111111111111111111111111123456789"
	key := "1234123412341234123412341234abcd"

	crypted, err := AesCbcPkcs7Encrypt([]byte(src), []byte(key), nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("base64UrlSafe result:", base64.URLEncoding.EncodeToString(crypted))
	data, err := AesCbcPkcs7Decrypt(crypted, []byte(key), nil)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("source is :", string(data))

}
