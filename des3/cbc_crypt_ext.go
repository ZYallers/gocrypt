package des3

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

func tripleDes3Encrypt(origData, des3key []byte) (encrypted []byte, encryptErr error) {
	defer recoverError(&encryptErr)
	block, encryptErr := des.NewTripleDESCipher(des3key)
	if encryptErr != nil {
		return
	}
	data := pkcs5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, des3key[:des.BlockSize])
	encrypted = make([]byte, len(data))
	blockMode.CryptBlocks(encrypted, data)
	return
}

func tripleDes3Decrypt(origData, des3key []byte) (decrypted []byte, decryptErr error) {
	defer recoverError(&decryptErr)
	block, decryptErr := des.NewTripleDESCipher(des3key)
	if decryptErr != nil {
		return
	}
	blockMode := cipher.NewCBCDecrypter(block, des3key[:8])
	decrypted = make([]byte, len(origData))
	blockMode.CryptBlocks(decrypted, origData)
	decrypted = pkcs5UnPadding(decrypted)
	return
}

func pkcs5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

func recoverError(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%v", r)
	}
}
