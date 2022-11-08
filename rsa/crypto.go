package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"math/big"
)

var bigZero, bigOne = big.NewInt(0), big.NewInt(1)

func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

func decrypt(random io.Reader, priKey *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priKey.N) > 0 {
		err = ErrDecryption
		return
	}
	var ir *big.Int
	if random != nil {
		var r *big.Int

		for {
			r, err = rand.Int(random, priKey.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			var ok bool
			ir, ok = modInverse(r, priKey.N)
			if ok {
				break
			}
		}
		bigE := big.NewInt(int64(priKey.E))
		rpowe := new(big.Int).Exp(r, bigE, priKey.N)
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priKey.N)
		c = cCopy
	}
	if priKey.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priKey.D, priKey.N)
	} else {
		m = new(big.Int).Exp(c, priKey.Precomputed.Dp, priKey.Primes[0])
		m2 := new(big.Int).Exp(c, priKey.Precomputed.Dq, priKey.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priKey.Primes[0])
		}
		m.Mul(m, priKey.Precomputed.Qinv)
		m.Mod(m, priKey.Primes[0])
		m.Mul(m, priKey.Primes[1])
		m.Add(m, m2)

		for i, values := range priKey.Precomputed.CRTValues {
			prime := priKey.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}
	if ir != nil {
		m.Mul(m, ir)
		m.Mod(m, priKey.N)
	}

	return
}

func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}

func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}
	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
			s[i] ^= 0x42
		}
	}
	return
}

func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}

func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		return
	}
	if x.Cmp(bigOne) < 0 {
		x.Add(x, n)
	}
	return x, true
}
