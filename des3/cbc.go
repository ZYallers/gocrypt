package des3

import (
	"crypto/cipher"
	"crypto/des"
	"github.com/ZYallers/gocrypt"
)

type Cbc struct {
	gocrypt.Base64
	des3key []byte
}

var CbcCrypto = Cbc{}

func (c *Cbc) SetDes3Key(des3key string) {
	c.des3key = []byte(des3key)
}

func (c *Cbc) Encrypt(input, iv []byte) (encByte []byte, encErr error) {
	defer gocrypt.RecoverError(&encErr)
	encByte, encErr = des3Encrypt(input, c.des3key, iv)
	return
}

func (c *Cbc) Decrypt(input, iv []byte) (decByte []byte, decErr error) {
	defer gocrypt.RecoverError(&decErr)
	decByte, decErr = des3Decrypt(input, c.des3key, iv)
	return
}

func des3Encrypt(data, des3key, iv []byte) (encrypted []byte, encryptErr error) {
	defer gocrypt.RecoverError(&encryptErr)
	block, encryptErr := des.NewTripleDESCipher(des3key)
	if encryptErr != nil {
		return
	}
	if len(iv) == 0 {
		iv = des3key[:des.BlockSize]
	}
	encryptBytes := gocrypt.PKCS7Padding(data, block.BlockSize())
	encrypted = make([]byte, len(encryptBytes))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(encrypted, encryptBytes)
	return
}

func des3Decrypt(data, des3key, iv []byte) (decrypted []byte, decryptErr error) {
	defer gocrypt.RecoverError(&decryptErr)
	block, decryptErr := des.NewTripleDESCipher(des3key)
	if decryptErr != nil {
		return
	}
	if len(iv) == 0 {
		iv = des3key[:des.BlockSize]
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	decrypted = make([]byte, len(data))
	blockMode.CryptBlocks(decrypted, data)
	decrypted = gocrypt.PKCS7UnPadding(decrypted)
	return
}
