package des3

import "testing"

const des3key = "123456788765432112345678"

func init() {
	CBCCrypter.SetDes3Key(des3key)
}

func TestDES3Crypt_Decrypt(t *testing.T) {
	const input = "sPH5yDbhyPCQmKemfdV7+zollbFhYqdWaz1q/S2T8izv+f3S2cF01NsamNxkYr/L/YmFVxMezrd/kvdCVTSC1CTmI1j8AOEC3VzDlA3loe3G2kMAlY+hW53VZyhvAJNARltuuWiHqrRdXdAVVQVQl2uEpm40vDVY"
	if b, err := CBCCrypter.Decrypt(CBCCrypter.Decode(input)); err != nil {
		t.Error(err)
	} else {
		t.Log(CBCCrypter.String(b))
	}
}

func TestDES3Crypt_Encrypt(t *testing.T) {
	const input = "3DES（又叫Triple DES）是三重数据加密算法（TDEA，Triple Data Encryption Algorithm）块密码的通称。"
	if b, err := CBCCrypter.Encrypt([]byte(input)); err != nil {
		t.Error(err)
	} else {
		t.Log(CBCCrypter.Encode(b))
	}
}
