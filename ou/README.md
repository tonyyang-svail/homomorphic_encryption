# Okamoto–Uchiyama Crypto-system

Implements simple OU described at [Wiki Page](https://en.wikipedia.org/wiki/Okamoto%E2%80%93Uchiyama_cryptosystem).

## Performance

key size = 2048 bits

Adding #dataSize integer under additive homomorphic.

```bash
go test -run TestAdditiveHomomorphic -v
=== RUN   TestAdditiveHomomorphic
dataSize:	10	time elapsed:	199.288412ms
dataSize:	100	time elapsed:	105.208351ms
dataSize:	1000	time elapsed:	310.11982ms
dataSize:	10000	time elapsed:	1.183977069s
dataSize:	100000	time elapsed:	13.197817237s
--- PASS: TestAdditiveHomomorphic (15.00s)
```
