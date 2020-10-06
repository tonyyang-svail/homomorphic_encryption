package ou

import (
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
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
