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

func (c *Cbc) Encrypt(input []byte) (encByte []byte, encErr error) {
	defer gocrypt.RecoverError(&encErr)
	encByte, encErr = des3Encrypt(input, c.des3key)
	return
}

func (c *Cbc) Decrypt(input []byte) (decByte []byte, decErr error) {
	defer gocrypt.RecoverError(&decErr)
	decByte, decErr = des3Decrypt(input, c.des3key)
	return
}

func des3Encrypt(data, des3key []byte) (encrypted []byte, encryptErr error) {
	defer gocrypt.RecoverError(&encryptErr)
	block, encryptErr := des.NewTripleDESCipher(des3key)
	if encryptErr != nil {
		return
	}
	encryptBytes := gocrypt.Pkcs5Padding(data, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, des3key[:des.BlockSize])
	encrypted = make([]byte, len(encryptBytes))
	blockMode.CryptBlocks(encrypted, encryptBytes)
	return
}

func des3Decrypt(data, des3key []byte) (decrypted []byte, decryptErr error) {
	defer gocrypt.RecoverError(&decryptErr)
	block, decryptErr := des.NewTripleDESCipher(des3key)
	if decryptErr != nil {
		return
	}
	blockMode := cipher.NewCBCDecrypter(block, des3key[:des.BlockSize])
	decrypted = make([]byte, len(data))
	blockMode.CryptBlocks(decrypted, data)
	decrypted = gocrypt.Pkcs5UnPadding(decrypted)
	return
}
