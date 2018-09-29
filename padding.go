package aescrypto

import (
	"bytes"
	"errors"
)

// PKCS5包装
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS5解包装
func PKCS7UnPadding(plantText []byte) ([]byte, error) {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	effectiveCount := length - unpadding
	if effectiveCount <= 0 {
		return nil, errors.New("The key does not support the ciphertext")
	}
	return plantText[:effectiveCount], nil
}

// PKCS5包装
func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

// PKCS5解包装
func PKCS5UnPadding(encrypt []byte) ([]byte, error) {
	padding := encrypt[len(encrypt)-1]
	effectiveCount := len(encrypt) - int(padding)
	if effectiveCount <= 0 {
		return nil, errors.New("The key does not support the ciphertext")
	}
	return encrypt[:effectiveCount], nil
}
