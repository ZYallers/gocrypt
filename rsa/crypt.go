package rsa

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io/ioutil"
)

type Crypt struct {
	pubKey    string
	priKey    string
	rsaPubKey *rsa.PublicKey
	rsaPriKey *rsa.PrivateKey
}

var (
	Crypter               = &Crypt{}
	ErrEncryptTypeNoFound = errors.New("encrypt type no found")
	ErrDecryptTypeNoFound = errors.New("decrypt type no found")
	ErrPubKeyNil          = errors.New(`please set public key in crypt`)
	ErrPriKeyNil          = errors.New(`please set private key in crypt`)
)

// 设置公钥
func (c *Crypt) SetPubKey(pubKey string) (err error) {
	c.pubKey = pubKey
	c.rsaPubKey, err = c.GetPubKey()
	return err
}

// 获取公钥
func (c *Crypt) GetPubKey() (*rsa.PublicKey, error) {
	return getPubKey([]byte(c.pubKey))
}

// 设置私钥
func (c *Crypt) SetPriKey(priKey string) (err error) {
	c.priKey = priKey
	c.rsaPriKey, err = c.GetPriKey()
	return err
}

// 获取私钥
func (c *Crypt) GetPriKey() (*rsa.PrivateKey, error) {
	return getPriKey([]byte(c.priKey))
}

type EncryptType int
type DecryptType int

const (
	EncryptPubKey EncryptType = 1
	DecryptPubKey DecryptType = 2
	EncryptPriKey EncryptType = 3
	DecryptPriKey DecryptType = 4
)

// 加密
func (c *Crypt) Encrypt(input []byte, typ EncryptType) ([]byte, error) {
	switch typ {
	case EncryptPubKey:
		return c.EncryptPubKey(input)
	case EncryptPriKey:
		return c.EncryptPriKey(input)
	default:
		return nil, ErrEncryptTypeNoFound
	}
}

// 解密
func (c *Crypt) Decrypt(input []byte, typ DecryptType) ([]byte, error) {
	switch typ {
	case DecryptPubKey:
		return c.DecryptPubKey(input)
	case DecryptPriKey:
		return c.DecryptPriKey(input)
	default:
		return nil, ErrDecryptTypeNoFound
	}
}

// 公钥加密
func (c *Crypt) EncryptPubKey(input []byte) ([]byte, error) {
	if c.rsaPubKey == nil {
		return nil, ErrPubKeyNil
	}
	output := bytes.NewBuffer(nil)
	err := cryptPubKeyIO(c.rsaPubKey, bytes.NewReader(input), output, true)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// 公钥解密
func (c *Crypt) DecryptPubKey(input []byte) ([]byte, error) {
	if c.rsaPubKey == nil {
		return nil, ErrPubKeyNil
	}
	output := bytes.NewBuffer(nil)
	err := cryptPubKeyIO(c.rsaPubKey, bytes.NewReader(input), output, false)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// 私钥加密
func (c *Crypt) EncryptPriKey(input []byte) ([]byte, error) {
	if c.rsaPriKey == nil {
		return nil, ErrPriKeyNil
	}
	output := bytes.NewBuffer(nil)
	err := cryptPriKeyIO(c.rsaPriKey, bytes.NewReader(input), output, true)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// 私钥解密
func (c *Crypt) DecryptPriKey(input []byte) ([]byte, error) {
	if c.rsaPriKey == nil {
		return nil, ErrPriKeyNil
	}
	output := bytes.NewBuffer(nil)
	err := cryptPriKeyIO(c.rsaPriKey, bytes.NewReader(input), output, false)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// byte转base64字符串
func (c *Crypt) Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// base64字符串转byte
func (c *Crypt) Decode(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(s); err != nil {
		return nil
	} else {
		return b
	}
}

// byte转string
func (c *Crypt) String(b []byte) string {
	return string(b)
}
