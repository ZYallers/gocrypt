package des3

import (
	"encoding/base64"
)

type CBCCrypt struct {
	des3key []byte
}

var CBCCrypter = CBCCrypt{}

// 设置des3key
func (c *CBCCrypt) SetDes3Key(des3key string) {
	c.des3key = []byte(des3key)
}

// 加密
func (c *CBCCrypt) Encrypt(input []byte) (encByte []byte, encErr error) {
	defer recoverError(&encErr)
	encByte, encErr = tripleDes3Encrypt(input, c.des3key)
	return
}

// 解密
func (c *CBCCrypt) Decrypt(input []byte) (decByte []byte, decErr error) {
	defer recoverError(&decErr)
	decByte, decErr = tripleDes3Decrypt(input, c.des3key)
	return
}

// byte转base64字符串
func (c *CBCCrypt) Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// base64字符串转byte
func (c *CBCCrypt) Decode(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(s); err != nil {
		return nil
	} else {
		return b
	}
}

// byte转string
func (c *CBCCrypt) String(b []byte) string {
	return string(b)
}
