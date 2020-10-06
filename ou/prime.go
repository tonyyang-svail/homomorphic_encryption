package ou

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
)

type primePairGenerator interface {
	Next() (*big.Int, *big.Int, error)
}

type rsaPrimePairGenerator struct {
	nBits int
}

func (p *rsaPrimePairGenerator) Next() (*big.Int, *big.Int, error) {
	key, err := rsa.GenerateKey(rand.Reader, p.nBits)
	if err != nil {
		return nil, nil, err
	}
	if len(key.Primes) != 2 {
		return nil, nil, fmt.Errorf("KeyGen: failed at generating two primes using RSA")
	}
	return key.Primes[0], key.Primes[1], nil
}
