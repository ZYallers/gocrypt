package rsa

import "errors"

var (
	ErrEncryptTypeNoFound = errors.New("encrypt type no found")
	ErrDecryptTypeNoFound = errors.New("decrypt type no found")
	ErrPubKeyNil          = errors.New(`please set public key in crypt`)
	ErrPriKeyNil          = errors.New(`please set private key in crypt`)
	ErrDataToLarge        = errors.New("message too long for rsa public key size")
	ErrDataLen            = errors.New("data length error")
	ErrDataBroken         = errors.New("data broken, first byte is not zero")
	ErrKeyPairMismatch    = errors.New("data is not encrypted by private key")
	ErrDecryption         = errors.New("decryption error")
	ErrGetPubKey          = errors.New("get public key error")
	ErrGetPriKey          = errors.New("get private key error")
)
