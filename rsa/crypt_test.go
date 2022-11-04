package rsa

import (
	"testing"
)

var PubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9jxNe1BcLJBbDyeRj80V
H1cfIs+3nF14EgffwoEa2lx14V4wFSaZQPQTmpS1j2Q9cCLLJC4evdb6jtiZpEDt
tXgtLkvHp3m4ITZqcujavP5UqJNowbsCZEh84GuG7qkaCx1jiTBMEAv3WMj0dwlV
hxLlrxlQf22WW+s0LiyuWAsxtAXeTLzoTNdRAWISDHX8r25zsjZzBC+vxDH/Y8GA
WHesgj/Mdb/5w7UiVOIJF0I4EtcD0kmWWq5Qo2mO1jldppvoM1tHpFpFxR2XGtPt
dgOkRV3WBKT+kEr4nqi/hkLYQSuQiCqRfEi9cZQimVsAdeNsBNQhbHn1+Ai1teoD
1wIDAQAB
-----END PUBLIC KEY-----
`

var PriKey = `-----BEGIN PRIVATE KEY-----
MIIEowIBAAKCAQEA9jxNe1BcLJBbDyeRj80VH1cfIs+3nF14EgffwoEa2lx14V4w
FSaZQPQTmpS1j2Q9cCLLJC4evdb6jtiZpEDttXgtLkvHp3m4ITZqcujavP5UqJNo
wbsCZEh84GuG7qkaCx1jiTBMEAv3WMj0dwlVhxLlrxlQf22WW+s0LiyuWAsxtAXe
TLzoTNdRAWISDHX8r25zsjZzBC+vxDH/Y8GAWHesgj/Mdb/5w7UiVOIJF0I4EtcD
0kmWWq5Qo2mO1jldppvoM1tHpFpFxR2XGtPtdgOkRV3WBKT+kEr4nqi/hkLYQSuQ
iCqRfEi9cZQimVsAdeNsBNQhbHn1+Ai1teoD1wIDAQABAoIBAADaVp5dueQBn/8e
cPehizgvkhEJzSYCgN73HgRLdC9bcKEWNW5tUsyRy9uWNkbH3xqbVD7M1hhsPTPv
diDGhMxDHUzywD9JQaUDzjyVp+RNsTdgQ1WgczKruZsBZFdBSLDPKkAYZbsMf4/U
KlybMKumGhuQJ+I5G/M3jle2mef+KDGoWl1Mc/3TNeqUp6NZZKi2H5okZEHoNgeL
8Kyh8cBBih4D0UOU//8eRgUBxIVrHdkcLRtVx5OJA3LWTLPDVGNGXUewlpER/uLx
9oXhYfTTYWGv/UZIiq3CWVsFopui7mTCxDZn7452vDNp1wYqPUkhLYzhc3d9mXF8
ZMGHhKECgYEA+qZdLfDrOXjYjnOubcGlIETf8WTjHZanqpofFynrB6VaTnrPa+pK
afXCnVENbU7TVRyhf/Nwox44LSPrzDiVPDnAxElrVwm5gXbGFGk5bd1yaxmaW2jB
YrBxD6UvxnCdwL0AWhbfjb5YQkV0F/8fPvjLVzq/fa+3xL5eYaTARicCgYEA+33R
Q1wGXDA+NLElTFKsw3zYlk1VI3hHz04yPClZ/Gu9Flr3ZJrzN7TVCua/tqOgNQg5
yBY8StiN1vqzSL9wFXdJCMlhjb81rdFUuiFbh0FZusk7EErl6DjpkbgSw8YYFrxg
P0UktpqmbXjEMzIu16Coy2tZCm29wXtCTWMuEtECgYAJQ1iyN/MZfqPSL+hEWiG2
HZWBIE9capLrtSJtArmS4MODnvpHbLMvU0vL8JDkd0NMI/C7/80r2hQNZwRx2a16
OlArcOMspklaxX7whir/Km3uE1YnBqoO8aJcB6jKVqMd2l5G9g1w+ZXdbR+rO1x2
QU+Se7NT+8h41ug6B5KrhQKBgGRoyYIxXcC06kEzcQbWA3BRilAINDPjNBiKyffH
MsxbX7VrQFcEnpLhOiYOFwEetzo1PIyshAoGCCuLEMW82U1YwOonLTHg49ewOjnO
U7Le3qp66YAJx10+S9MIQUW0860wLOVV/+CAQm52xy8BnD4vQPVmuLg3NInpYoFv
VdfhAoGBAJvlFW5MSvklFiBdYiDpI4TZ4T5AbthM2+HzUONyTZOqL++6xsqNZ3g1
pUPK39jiOO3USu/xOCVYUWJhD0awYzXK36ufd0ZF8uFPzNwleu82XXKVVTaG+7eo
7pkTAK3/D60jl/S2dRwpCGQViOpshOVasQE1i6skMknTWqEvrJh1
-----END PRIVATE KEY-----
`

func TestCrypt_SetPubKey(t *testing.T) {
	if err := Crypter.SetPubKey(PubKey); err != nil {
		t.Error(err)
	} else {
		t.Log(Crypter.GetPubKey())
	}
}

func TestCrypt_SetPriKey(t *testing.T) {
	if err := Crypter.SetPriKey(PriKey); err != nil {
		t.Error(err)
	} else {
		t.Log(Crypter.GetPriKey())
	}
}

// 公钥加密私钥解密
func TestCrypt_EncryptPubKey_DecryptPriKey(t *testing.T) {
	if err := Crypter.SetPubKey(PubKey); err != nil {
		t.Error(err)
	}
	if err := Crypter.SetPriKey(PriKey); err != nil {
		t.Error(err)
	}
	const input = "hello rsa"
	encrypted, err := Crypter.EncryptPubKey([]byte(input))
	t.Log("EncryptPubKey:", Crypter.Encode(encrypted))
	if err != nil {
		t.Error(err)
	}

	decrypted, err := Crypter.DecryptPriKey(encrypted)
	t.Log("DecryptPriKey:", Crypter.String(decrypted))
	if err != nil {
		t.Error(err)
	}
	if string(decrypted) != input {
		t.Error(`不符合预期`)
	}
}

// 公钥解密私钥加密
func TestCrypt_EncryptPriKey_DecryptPubKey(t *testing.T) {
	if err := Crypter.SetPubKey(PubKey); err != nil {
		t.Error(err)
	}
	if err := Crypter.SetPriKey(PriKey); err != nil {
		t.Error(err)
	}
	const input = "hello rsa"
	encrypted, err := Crypter.EncryptPriKey([]byte(input))
	t.Log("EncryptPriKey:", Crypter.Encode(encrypted))
	if err != nil {
		t.Error(err)
	}
	decrypted, err := Crypter.DecryptPubKey(encrypted)
	t.Log("DecryptPubKey:", Crypter.String(decrypted))
	if err != nil {
		t.Error(err)
	}
	if string(decrypted) != input {
		t.Error(`不符合预期`)
	}
}

func TestCrypt_Encrypt(t *testing.T) {
	if err := Crypter.SetPubKey(PubKey); err != nil {
		t.Error(err)
	}
	if err := Crypter.SetPriKey(PriKey); err != nil {
		t.Error(err)
	}
	var input = []byte("hello rsa")
	if bte, err := Crypter.Encrypt(input, EncryptPubKey); err != nil {
		t.Error(err)
	} else {
		t.Log("EncryptPubKey", Crypter.Encode(bte))
	}
	if bte, err := Crypter.Encrypt(input, EncryptPriKey); err != nil {
		t.Error(err)
	} else {
		t.Log("EncryptPriKey", Crypter.Encode(bte))
	}
}

func TestCrypt_Decrypt(t *testing.T) {
	if err := Crypter.SetPubKey(PubKey); err != nil {
		t.Error(err)
	}
	if err := Crypter.SetPriKey(PriKey); err != nil {
		t.Error(err)
	}
	s := "Oacl0SwoeeeVcwNroJDz/U/yt42q1h2wPLjazmoOh4wQw2qyct2n0eVfov1RfG8iq41mBsWDYBDyOitHzcLXQyt3xUPv0BVj1+3bsknC8opfpVY35PApS4YBy7SsB0KOl10Avz6gmY7dL1HWwrMsB5ACGgPqXbxdSquVDL3m8/048IbUD2zv/TpVjbxa8sZ+FymlkGQQOE7+RQQgtONiQEvYhTzF10dHnScjN9D39Nky3HADM+ltXsg5Ld3KDRVNMnjmqyZ4snUEO5RdFTBnGFIpKa0lHazPfL8jQhybp328+gD4lRTOZ9R6POId0Efh6wIbBmchlGZtru27L8TGIA=="
	if bte, err := Crypter.Decrypt(Crypter.Decode(s), DecryptPubKey); err != nil {
		t.Error(err)
	} else {
		t.Log("DecryptPubKey", Crypter.String(bte))
	}
	s = "H854jxBGVu5EUwJRsdWlGLO8Q1QST/gzUG24sqQkqts5G/FhMpBubapsnyfTAbnz16I6MQDvCGKBQG1fGfDDJHi3XJjhLKpjGODJRuY8LQWgMttbuzi3RxmtpYppiwqHVl/VPl+7Elz0vpaN0Z2OLTrdHDc+Xq6V2ZiqD3xVMeFHqIbRFOGK+DGyTvKtsbri0fgTt5AdDxAtKUMQwQx2PKHre1OqQJGTq6Mwv6QUJj/BwcQ4e8r1qu6a6i9F3JojJXlekZsMrAt1YwJPlyukSyZbu7q1d1BfCxGE0K44W3T+Yiida6pXpPY+qYJyw2G68FZjQlLNK3vtCHS5w2WGkw=="
	if bte, err := Crypter.Decrypt(Crypter.Decode(s), DecryptPriKey); err != nil {
		t.Error(err)
	} else {
		t.Log("DecryptPriKey", Crypter.String(bte))
	}
}
