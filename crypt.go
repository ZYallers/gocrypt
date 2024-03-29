package gocrypt

import (
	"bytes"
	"fmt"
)

func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func PKCS7UnPadding(data []byte) []byte {
	length := len(data)
	unPadding := int(data[length-1])
	return data[:(length - unPadding)]
}

func RecoverError(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%v", r)
	}
}
