package des3

import "testing"

const des3key = "PH5yDbhyPCQmKemfdV7S2T8N"

func init() {
	CbcCrypto.SetDes3Key(des3key)
}

func TestCbc_Decrypt(t *testing.T) {
	const input = "+BAT9p9GReOVJxfGd3iBrQfZ/qFfMjh0GGfVBU4Lre256OWExEzVnwKayRGTy+qwqS2BWFAA/ESGCeXoA1vlvFYLptMpFdvm/K9SFnahExcpB+AV1erAAKurZuwZHKY0iRSekZ6atmwkMhILAV7uFSYWx7lCDBr8"
	if b, err := CbcCrypto.Decrypt(CbcCrypto.Decode(input)); err != nil {
		t.Error(err)
	} else {
		t.Log(CbcCrypto.String(b))
	}
}

func TestCbc_Encrypt(t *testing.T) {
	const input = "3DES（又叫Triple DES）是三重数据加密算法（TDEA，Triple Data Encryption Algorithm）块密码的通称。"
	if b, err := CbcCrypto.Encrypt([]byte(input)); err != nil {
		t.Error(err)
	} else {
		t.Log(CbcCrypto.Encode(b))
	}
}
