package ou

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
)

func genTwoPrimes(useRSA bool) (*big.Int, *big.Int, error) {
	if useRSA {
		key, err := rsa.GenerateKey(rand.Reader, nBits)
		if err != nil {
			return nil, nil, err
		}
		if len(key.Primes) != 2 {
			return nil, nil, fmt.Errorf("KeyGen: failed at generating two primes using RSA")
		}
		return key.Primes[0], key.Primes[1], nil
	}

	return big.NewInt(3), big.NewInt(5), nil
}

func KeyGen(useRSA bool) (*publicKey, *privateKey, error) {
	p, q, err := genTwoPrimes(useRSA)
	if err != nil {
		return nil, nil, err
	}

	n := big.NewInt(1)
	n.Mul(p, p)
	n.Mul(n, q)

	g := big.NewInt(1)
	for i := int64(2); ; i++ {
		pSquare := big.NewInt(1)
		pSquare.Mul(p, p)
		pMinusOne := big.NewInt(1)
		pMinusOne.Sub(p, big.NewInt(1))

		g.Exp(big.NewInt(i), pMinusOne, pSquare)
		if g.Cmp(big.NewInt(1)) != 0 {
			break
		}
	}

	h := big.NewInt(1)
	h.Exp(g, n, n)

	return &publicKey{n, g, h}, &privateKey{p, q}, nil
}

type randIntGen interface {
	Next() *big.Int
}

func Encrypt(key *publicKey, m *big.Int, gen randIntGen) *big.Int {
	r := gen.Next()

	left := big.NewInt(1)
	left.Exp(key.g, m, key.n)

	right := big.NewInt(1)
	right.Exp(key.h, r, key.n)

	c := big.NewInt(1)
	c.Mul(left, right)
	c.Mod(c, key.n)

	return c
}

func Decrypt(pub *publicKey, priv *privateKey, c *big.Int) *big.Int {
	pSquare := big.NewInt(1)
	pSquare.Mul(priv.p, priv.p)
	pMinusOne := big.NewInt(1)
	pMinusOne.Sub(priv.p, big.NewInt(1))

	a := big.NewInt(1)
	a.Exp(c, pMinusOne, pSquare)
	a.Sub(a, big.NewInt(1))
	a.Div(a, priv.p)

	b := big.NewInt(1)
	b.Exp(pub.g, pMinusOne, pSquare)
	b.Sub(b, big.NewInt(1))
	b.Div(b, priv.p)

	bInverse := inverse(b, priv.p)

	answer := big.NewInt(1)
	answer.Mul(a, bInverse)
	answer.Mod(answer, priv.p)
	return answer
}

// find inverse using extended euclidean algorithm
func inverse(a, m *big.Int) *big.Int {
	qq := []*big.Int{big.NewInt(0), big.NewInt(0)}
	rr := []*big.Int{a, m}
	ss := []*big.Int{big.NewInt(1), big.NewInt(0)}
	tt := []*big.Int{big.NewInt(0), big.NewInt(1)}

	zero := big.NewInt(0)
	for {
		if rr[len(rr)-1].Cmp(zero) == 0 {
			break
		}

		l := len(qq)
		q, r, s, t := big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)

		q.Div(rr[l-2], rr[l-1])

		r.Mul(q, rr[l-1])
		r.Sub(rr[l-2], r)

		s.Mul(q, ss[l-1])
		s.Sub(ss[l-2], s)

		t.Mul(q, tt[l-1])
		t.Sub(tt[l-2], t)

		qq = append(qq, q)
		rr = append(rr, r)
		ss = append(ss, s)
		tt = append(tt, t)
	}

	answer := big.NewInt(1)
	return answer.Mod(ss[len(ss)-2], m)
}
