package rsa

import (
	"bytes"
	"crypto/rsa"
	"github.com/ZYallers/gocrypt"
	"io/ioutil"
)

type (
	Crypt struct {
		gocrypt.Base64
		pubKey    string
		priKey    string
		rsaPubKey *rsa.PublicKey
		rsaPriKey *rsa.PrivateKey
	}
	EncryptType uint8
	DecryptType uint8
)

const (
	PubKeyEncrypt EncryptType = 1
	PubKeyDecrypt DecryptType = 2
	PriKeyEncrypt EncryptType = 3
	PriKeyDecrypt DecryptType = 4
)

var Crypto = Crypt{}

func (c *Crypt) SetPubKey(pubKey string) (err error) {
	c.pubKey = pubKey
	c.rsaPubKey, err = c.GetPubKey()
	return err
}

func (c *Crypt) GetPubKey() (*rsa.PublicKey, error) {
	return getPubKey([]byte(c.pubKey))
}

func (c *Crypt) SetPriKey(priKey string) (err error) {
	c.priKey = priKey
	c.rsaPriKey, err = c.GetPriKey()
	return err
}

func (c *Crypt) GetPriKey() (*rsa.PrivateKey, error) {
	return getPriKey([]byte(c.priKey))
}

func (c *Crypt) Encrypt(input []byte, typ EncryptType) ([]byte, error) {
	switch typ {
	case PubKeyEncrypt:
		return c.PubKeyEncrypt(input)
	case PriKeyEncrypt:
		return c.PriKeyEncrypt(input)
	default:
		return nil, ErrEncryptTypeNoFound
	}
}

func (c *Crypt) Decrypt(input []byte, typ DecryptType) ([]byte, error) {
	switch typ {
	case PubKeyDecrypt:
		return c.PubKeyDecrypt(input)
	case PriKeyDecrypt:
		return c.PriKeyDecrypt(input)
	default:
		return nil, ErrDecryptTypeNoFound
	}
}

func (c *Crypt) PubKeyEncrypt(input []byte) ([]byte, error) {
	if c.rsaPubKey == nil {
		return nil, ErrPubKeyNil
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIoCrypt(c.rsaPubKey, bytes.NewReader(input), output, true)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

func (c *Crypt) PubKeyDecrypt(input []byte) ([]byte, error) {
	if c.rsaPubKey == nil {
		return nil, ErrPubKeyNil
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIoCrypt(c.rsaPubKey, bytes.NewReader(input), output, false)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

func (c *Crypt) PriKeyEncrypt(input []byte) ([]byte, error) {
	if c.rsaPriKey == nil {
		return nil, ErrPriKeyNil
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIoCrypt(c.rsaPriKey, bytes.NewReader(input), output, true)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

func (c *Crypt) PriKeyDecrypt(input []byte) ([]byte, error) {
	if c.rsaPriKey == nil {
		return nil, ErrPriKeyNil
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIoCrypt(c.rsaPriKey, bytes.NewReader(input), output, false)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}
