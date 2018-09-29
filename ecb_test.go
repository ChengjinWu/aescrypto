package aescrypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"testing"
)

func Test_ecb(t *testing.T) {
	/*
	*src 要加密的字符串
	*key 用来加密的密钥 密钥长度可以是128bit、192bit、256bit中的任意一个
	*16位key对应128bit
	 */
	src := "200"
	key := "d201e68d1fe59792c308ca0b79b03d29"

	crypted, err := AesEcbPkcs5Encrypt([]byte(src), []byte(key))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("base64UrlSafe result:", base64.URLEncoding.EncodeToString(crypted))
	data, err := AesEcbPkcs5Decrypt(crypted, []byte(key))

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("source is :", string(data))
}

func Test_ecb2(t *testing.T) {
	/*
	*src 要加密的字符串
	*key 用来加密的密钥 密钥长度可以是128bit、192bit、256bit中的任意一个
	*16位key对应128bit
	 */

	key := []byte("57d065d2f3442d968ecb9fc4f21847ef")

	cipherHexText := []byte("bQCXBJeiHz9maEMOpOio5Q")
	fmt.Println(qtfmDecrypt(cipherHexText, key, key))
}
func qtfmDecrypt(cipher, ekey, ikey []byte, args ...interface{}) (float64, error) {
	equalSignLen := 4 - len(cipher)%4
	for i := 0; i < equalSignLen; i++ {
		cipher = append(cipher, '=')
	}
	crypted,err := base64.URLEncoding.DecodeString(string(cipher))
	if err != nil {
		return 0, err
	}
	data, err := AesEcbPkcs5Decrypt(crypted, []byte(ekey))
	if err != nil {
		return 0, err
	}
	f, err := strconv.ParseFloat(string(data), 64)
	if err != nil {
		return 0, err
	}
	return f, nil
}
