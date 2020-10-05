package ou

import (
	"fmt"
	"math/big"
)

const nBits = 16

type publicKey struct {
	n *big.Int
	g *big.Int
	h *big.Int
}

func (k *publicKey) String() string {
	return fmt.Sprintf("%v, %v, %v", k.n.String(), k.g.String(), k.h.String())
}

type privateKey struct {
	p *big.Int
	q *big.Int
}

func (k *privateKey) String() string {
	return fmt.Sprintf("%v, %v", k.p.String(), k.q.String())
}
