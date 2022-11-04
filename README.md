# gocrypt

[![Go Report Card](https://goreportcard.com/badge/github.com/ZYallers/gocrypt)](https://goreportcard.com/report/github.com/ZYallers/gocrypt)
[![MIT license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.org/ZYallers/gocrypt.svg?branch=master)](https://travis-ci.org/ZYallers/gocrypt)
[![Foundation](https://img.shields.io/badge/Golang-Foundation-green.svg)](http://golangfoundation.org)
[![GoDoc](https://pkg.go.dev/badge/github.com/ZYallers/gocrypt?status.svg)](https://pkg.go.dev/github.com/ZYallers/gocrypt?tab=doc)
[![Sourcegraph](https://sourcegraph.com/github.com/ZYallers/gocrypt/-/badge.svg)](https://sourcegraph.com/github.com/ZYallers/gocrypt?badge)
[![Release](https://img.shields.io/github/release/ZYallers/gocrypt.svg?style=flat-square)](https://github.com/ZYallers/gocrypt/releases)
[![TODOs](https://badgen.net/https/api.tickgit.com/badgen/github.com/ZYallers/gocrypt)](https://www.tickgit.com/browse?repo=github.com/ZYallers/gocrypt)
[![goproxy.cn](https://goproxy.cn/stats/github.com/ZYallers/gocrypt/badges/download-count.svg)](https://goproxy.cn)

`gocrypt`用Go语言实现了3DES加解密、RSA加解密、RSA私钥加密公钥解密、RSA公钥加密私钥解密。

## 如何使用

1. 首先需要安装Go（需要1.15+版本），然后可以使用下面的Go命令导入`gocrypt`包。

```bash 
$ go get github.com/ZYallers/gocrypt
 ```

2. 使用案例：

```go
package main

import (
	"fmt"
	"github.com/ZYallers/gocrypt/des3"
	"github.com/ZYallers/gocrypt/rsa"
)

const (
	des3key = "123456788765432112345678"
	pubKey  = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9jxNe1BcLJBbDyeRj80V
H1cfIs+3nF14EgffwoEa2lx14V4wFSaZQPQTmpS1j2Q9cCLLJC4evdb6jtiZpEDt
tXgtLkvHp3m4ITZqcujavP5UqJNowbsCZEh84GuG7qkaCx1jiTBMEAv3WMj0dwlV
hxLlrxlQf22WW+s0LiyuWAsxtAXeTLzoTNdRAWISDHX8r25zsjZzBC+vxDH/Y8GA
WHesgj/Mdb/5w7UiVOIJF0I4EtcD0kmWWq5Qo2mO1jldppvoM1tHpFpFxR2XGtPt
dgOkRV3WBKT+kEr4nqi/hkLYQSuQiCqRfEi9cZQimVsAdeNsBNQhbHn1+Ai1teoD
1wIDAQAB
-----END PUBLIC KEY-----
`
	priKey = `-----BEGIN PRIVATE KEY-----
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
)

func init() {
	des3.CBCCrypter.SetDes3Key(des3key)
	if err := rsa.Crypter.SetPubKey(pubKey); err != nil {
		panic(err)
	}
	if err := rsa.Crypter.SetPriKey(priKey); err != nil {
		panic(err)
	}
}

func main() {
	const input = "hello des3"
	b, err := des3.CBCCrypter.Encrypt([]byte(input))
	if err != nil {
		panic(err)
	}
	fmt.Println("des3加密=", des3.CBCCrypter.Encode(b))
	b, err = des3.CBCCrypter.Decrypt(b)
	if err != nil {
		panic(err)
	}
	fmt.Println("des3解密=", des3.CBCCrypter.String(b))

	const input2 = "hello rsa"
	if bte, err := rsa.Crypter.Encrypt([]byte(input2), rsa.EncryptPubKey); err != nil {
		panic(err)
	} else {
		fmt.Println("rsa公钥加密=", rsa.Crypter.Encode(bte))
		if b, err := rsa.Crypter.Decrypt(bte, rsa.DecryptPriKey); err != nil {
			panic(err)
		} else {
			fmt.Println("rsa私钥解密=", rsa.Crypter.String(b))
		}
	}
	if bte, err := rsa.Crypter.Encrypt([]byte(input2), rsa.EncryptPriKey); err != nil {
		panic(err)
	} else {
		fmt.Println("rsa私钥加密=", rsa.Crypter.Encode(bte))
		if b, err := rsa.Crypter.Decrypt(bte, rsa.DecryptPubKey); err != nil {
			panic(err)
		} else {
			fmt.Println("rsa公钥解密=", rsa.Crypter.String(b))
		}
	}
}
```

运行输出结果：

```
des3加密= Le0/5Y6fCSQliYsxt0BvUw==
des3解密= hello des3
rsa公钥加密= vl6Tpz5/Li2aiuOp2/UTOoC5jeywf7yQ/MqmMKWPEQbOAhArQoYsatp8QTZSn7I4nbZZnENEirhRImX9N8H6N8JxWPgGH7Qb+yzomGan3GzEgu8A8no2vJqfbhO+d+3kQQlBBtVcTD4fhT/aVwd3SbJAGDKoPV4GauoNvzrz153/cSSgQtaoL53zMiPnwx/ouwfSvRobQ0BRWIpmahqiFRrRu3GBDh4PKjhqNDDdfubWRZqjGEHyIKM7Vh/98XKpLmMLb95gf53ZGV/BhTHKLNjBqeEGjvoz5w9Se8CSngwmKOMdZlA1w9oYY6jLsZJJOz+Cgpgl6jj35zY4gg==
rsa私钥解密= hello rsa
rsa私钥加密= Oacl0SwoeeeVcwNroJDz/U/yt42q1h2wPLjazmoOh4wQw2qyct2n0eVfov1RfG8iq41mBsWDYBDyOitHzcLXQyt3xUPv0BVj1+3bsknC8opfpVY35PApS4YBy7SsB0KOl10Avz6gmY7dL1HWwrMsB5ACGgPqXbxdSquVDL3m8/048IbUD2zv/TpVjbx+FymlkGQQOE7+RQQgtONiQEvYhTzF10dHnScjN9D39Nky3HADM+ltXsg5Ld3KDRVNMnjmqyZ4snUEO5RdFTBnGFIpKa0lHazPfL8jQhybp328+gD4lRTOZ9R6POId0Efh6wIbBmchlGZtru27L8TGIA==
rsa公钥解密= hello rsa
```

## License

Released under the [MIT License](https://github.com/ZYallers/gocrypt/blob/master/LICENSE)