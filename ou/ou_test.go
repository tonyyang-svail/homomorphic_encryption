package ou

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type mockPrimePairGen struct{}

func (*mockPrimePairGen) Next() (*big.Int, *big.Int, error) {
	return big.NewInt(3), big.NewInt(5), nil
}

func TestKeyGen(t *testing.T) {
	r := require.New(t)

	pub, priv, err := KeyGen(&mockPrimePairGen{})
	r.NoError(err)

	r.Equal(big.NewInt(int64(45)), pub.n)
	r.Equal(big.NewInt(int64(4)), pub.g)
	r.Equal(big.NewInt(int64(19)), pub.h)

	r.Equal(big.NewInt(int64(3)), priv.p)
	r.Equal(big.NewInt(int64(5)), priv.q)
}

type mockIntGen struct{}

func (*mockIntGen) Next() *big.Int {
	return big.NewInt(int64(1))
}

func TestEncrypt(t *testing.T) {
	r := require.New(t)

	pub := &publicKey{
		n: big.NewInt(int64(45)),
		g: big.NewInt(int64(4)),
		h: big.NewInt(int64(19)),
	}
	m := big.NewInt(int64(2))

	c := Encrypt(pub, m, &mockIntGen{})

	// 2^3 * 19^1 mod 45 = 1
	r.Equal(big.NewInt(34), c)
}

func TestInverse(t *testing.T) {
	r := require.New(t)

	r.Equal(big.NewInt(2), inverse(big.NewInt(2), big.NewInt(3)))
	r.Equal(big.NewInt(3), inverse(big.NewInt(2), big.NewInt(5)))
	r.Equal(big.NewInt(4), inverse(big.NewInt(2), big.NewInt(7)))
	r.Equal(big.NewInt(4), inverse(big.NewInt(4), big.NewInt(5)))
}

func TestDecrypt(t *testing.T) {
	r := require.New(t)

	pub := &publicKey{
		n: big.NewInt(int64(45)),
		g: big.NewInt(int64(4)),
		h: big.NewInt(int64(19)),
	}
	priv := &privateKey{
		p: big.NewInt(3),
		q: big.NewInt(5),
	}

	c := big.NewInt(34)
	r.Equal(big.NewInt(2), Decrypt(pub, priv, c))
}

type incIntGen struct {
	count int64
}

func (g *incIntGen) Next() *big.Int {
	g.count = g.count + 1
	return big.NewInt(g.count)
}

func TestAdditiveHomomorphic(t *testing.T) {
	r := require.New(t)

	for _, dataSize := range []int64{10, 100, 1000, 10000, 100000} {
		start := time.Now()

		pub, priv, err := KeyGen(&rsaPrimePairGenerator{nBits: 2048})
		r.NoError(err)

		ms := []*big.Int{}
		for i := int64(1); i <= dataSize; i++ {
			ms = append(ms, big.NewInt(1))
		}

		intGen := &incIntGen{}
		cs := []*big.Int{}
		for _, m := range ms {
			cs = append(cs, Encrypt(pub, m, intGen))
		}

		mul := big.NewInt(1)
		for _, c := range cs {
			mul.Mul(mul, c)
			mul.Mod(mul, pub.n)
		}

		r.Equal(big.NewInt(dataSize), Decrypt(pub, priv, mul))

		elapsed := time.Since(start)
		fmt.Printf("dataSize:\t%v\ttime elapsed:\t%v\n", dataSize, elapsed)
	}
}
