package gocrypt

import "encoding/base64"

type Base64 struct {
}

func (b *Base64) Encode(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}

func (b *Base64) Decode(s string) ([]byte, error) {
	if dec, err := base64.StdEncoding.DecodeString(s); err != nil {
		return nil, err
	} else {
		return dec, nil
	}
}

func (b *Base64) String(bytes []byte) string {
	return string(bytes)
}
