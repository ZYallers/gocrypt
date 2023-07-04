package aes

import (
	"strings"
	"testing"
)

const aesKey = "I98NTHNPezFnbe8iCaSc1xMPAv8ZtTil"

func init() {
	CbcCrypto.SetAesKey(aesKey)
}

func TestCbc_Decrypt(t *testing.T) {
	input := "/LJvP0J/zOcvjWq9jktEbUBiz6nxqLcN+/79HCl8pnaY6b/R/e0HFPfSq4OkRXaz9Jv96Vb31dQRFeY9O5QWJoC+sm3adEY5FJh2nzqy3Hstg6Gh9JzThsYdGYTFlsADWGX76thaj3f3SZ3uAq/IJQ=="
	decByte, err := CbcCrypto.Decode(input)
	if err != nil {
		t.Error(err)
		return
	}
	if b, err := CbcCrypto.Decrypt(decByte, nil); err != nil {
		t.Error(err)
	} else {
		t.Log(CbcCrypto.String(b))
	}

	iv := []byte(strings.Repeat("8", 16))
	input = "gO4OXKHKe+pao1++YTspD1zobhjPAexMDGwyMRxO1oj2I3bOlX9tZgnRNgIryAgKxq8F9XgBQuLkT6Qx6nuGEgqo3ryhuMBTRttpwlXupT5ZCwCUCAR++R7YRFJu46pJnkJYAtmX6m++OAs34NKKyg=="
	decByte, err = CbcCrypto.Decode(input)
	if err != nil {
		t.Error(err)
		return
	}
	if b, err := CbcCrypto.Decrypt(decByte, iv); err != nil {
		t.Error(err)
	} else {
		t.Log(CbcCrypto.String(b))
	}
}

func TestCbc_Encrypt(t *testing.T) {
	const input = "AES( advanced encryption standard)使用相同密钥进行加密和解密，也就是对称加密。"
	if b, err := CbcCrypto.Encrypt([]byte(input), nil); err != nil {
		t.Error(err)
	} else {
		t.Log(CbcCrypto.Encode(b))
	}
	iv := []byte(strings.Repeat("8", 16))
	if b, err := CbcCrypto.Encrypt([]byte(input), iv); err != nil {
		t.Error(err)
	} else {
		t.Log(CbcCrypto.Encode(b))
	}
}
