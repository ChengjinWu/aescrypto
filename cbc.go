package aescrypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// aes、cbc、pkcs7 加密
func AesCbcPkcs7Encrypt(plantText, key, ikey []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) //选择加密算法
	if err != nil {
		return nil, err
	}
	plantText = PKCS7Padding(plantText, block.BlockSize())
	if ikey == nil {
		ikey = key
	}
	blockModel := cipher.NewCBCEncrypter(block, ikey[:block.BlockSize()])
	ciphertext := make([]byte, len(plantText))
	blockModel.CryptBlocks(ciphertext, plantText)
	return ciphertext, nil
}

// aes、cbc、pkcs7 解密
func AesCbcPkcs7Decrypt(ciphertext, key, ikey []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) //选择解密算法
	if err != nil {
		return nil, err
	}
	if ikey == nil {
		ikey = key
	}
	blockModel := cipher.NewCBCDecrypter(block, ikey[:block.BlockSize()])
	plantText := make([]byte, len(ciphertext))
	blockModel.CryptBlocks(plantText, ciphertext)
	plantText = PKCS7UnPadding(plantText)
	return plantText, nil
}
