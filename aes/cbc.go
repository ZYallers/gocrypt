package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/ZYallers/gocrypt"
)

type Cbc struct {
	gocrypt.Base64
	aesKey []byte
}

var CbcCrypto = Cbc{}

func (c *Cbc) SetAesKey(aesKey string) {
	c.aesKey = []byte(aesKey)
}

func (c *Cbc) Encrypt(input, iv []byte) (encByte []byte, encErr error) {
	defer gocrypt.RecoverError(&encErr)
	encByte, encErr = aesEncrypt(input, c.aesKey, iv)
	return
}

func (c *Cbc) Decrypt(input, iv []byte) (decByte []byte, decErr error) {
	defer gocrypt.RecoverError(&decErr)
	decByte, decErr = aesDecrypt(input, c.aesKey, iv)
	return
}

func aesEncrypt(data, aesKey, iv []byte) (encrypted []byte, encryptErr error) {
	defer gocrypt.RecoverError(&encryptErr)
	block, encryptErr := aes.NewCipher(aesKey)
	if encryptErr != nil {
		return
	}
	blockSize := block.BlockSize()
	encryptBytes := gocrypt.PKCS7Padding(data, blockSize)
	if len(iv) == 0 {
		iv = aesKey[:blockSize]
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)
	encrypted = make([]byte, len(encryptBytes))
	blockMode.CryptBlocks(encrypted, encryptBytes)
	return
}

func aesDecrypt(data, aesKey, iv []byte) (decrypted []byte, decryptErr error) {
	defer gocrypt.RecoverError(&decryptErr)
	block, decryptErr := aes.NewCipher(aesKey)
	if decryptErr != nil {
		return
	}
	blockSize := block.BlockSize()
	if len(iv) == 0 {
		iv = aesKey[:blockSize]
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	decrypted = make([]byte, len(data))
	blockMode.CryptBlocks(decrypted, data)
	decrypted = gocrypt.PKCS7UnPadding(decrypted)
	return
}
