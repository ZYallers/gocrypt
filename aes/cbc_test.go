package aes

import "testing"

const aesKey = "I98NTHNPezFnbe8iCaSc1xMPAv8ZtTil"

func init() {
	CbcCrypto.SetAesKey(aesKey)
}

func TestCbc_Decrypt(t *testing.T) {
	const input = "/LJvP0J/zOcvjWq9jktEbUBiz6nxqLcN+/79HCl8pnaY6b/R/e0HFPfSq4OkRXaz9Jv96Vb31dQRFeY9O5QWJoC+sm3adEY5FJh2nzqy3Hstg6Gh9JzThsYdGYTFlsADWGX76thaj3f3SZ3uAq/IJQ=="
	if b, err := CbcCrypto.Decrypt(CbcCrypto.Decode(input)); err != nil {
		t.Error(err)
	} else {
		t.Log(CbcCrypto.String(b))
	}
}

func TestCbc_Encrypt(t *testing.T) {
	const input = "AES( advanced encryption standard)使用相同密钥进行加密和解密，也就是对称加密。"
	if b, err := CbcCrypto.Encrypt([]byte(input)); err != nil {
		t.Error(err)
	} else {
		t.Log(CbcCrypto.Encode(b))
	}
}
