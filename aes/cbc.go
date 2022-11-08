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

func (c *Cbc) Encrypt(input []byte) (encByte []byte, encErr error) {
	defer gocrypt.RecoverError(&encErr)
	encByte, encErr = aesEncrypt(input, c.aesKey)
	return
}

func (c *Cbc) Decrypt(input []byte) (decByte []byte, decErr error) {
	defer gocrypt.RecoverError(&decErr)
	decByte, decErr = aesDecrypt(input, c.aesKey)
	return
}

func aesEncrypt(data, aesKey []byte) (encrypted []byte, encryptErr error) {
	defer gocrypt.RecoverError(&encryptErr)
	block, encryptErr := aes.NewCipher(aesKey)
	if encryptErr != nil {
		return
	}
	blockSize := block.BlockSize()
	encryptBytes := gocrypt.Pkcs5Padding(data, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, aesKey[:blockSize])
	encrypted = make([]byte, len(encryptBytes))
	blockMode.CryptBlocks(encrypted, encryptBytes)
	return
}

func aesDecrypt(data, aesKey []byte) (decrypted []byte, decryptErr error) {
	defer gocrypt.RecoverError(&decryptErr)
	block, decryptErr := aes.NewCipher(aesKey)
	if decryptErr != nil {
		return
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, aesKey[:blockSize])
	decrypted = make([]byte, len(data))
	blockMode.CryptBlocks(decrypted, data)
	decrypted = gocrypt.Pkcs5UnPadding(decrypted)
	return
}
