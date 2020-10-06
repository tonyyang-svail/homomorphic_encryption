# Okamoto–Uchiyama Crypto-system

Implements simple OU described at [Wiki Page](https://en.wikipedia.org/wiki/Okamoto%E2%80%93Uchiyama_cryptosystem).

## Performance

Steps:

1. Generate key in 2048 bits.
1. Encrypt #dataSize integer. O(kn)
1. Adding #dataSize integer under additive homomorphic. O(kn)
1. Decrypt the sum, i.e. one integer.

```bash
go test -run TestAdditiveHomomorphic -v
=== RUN   TestAdditiveHomomorphic
-----------------
dataSize:	10	key gen:	159.539985ms
dataSize:	10	encrypt:	1.30457ms
dataSize:	10	homoAdd:	56.571µs
dataSize:	10	decrypt:	3.630294ms
-----------------
dataSize:	100	key gen:	190.449795ms
dataSize:	100	encrypt:	4.261933ms
dataSize:	100	homoAdd:	524.898µs
dataSize:	100	decrypt:	3.848473ms
-----------------
dataSize:	1000	key gen:	153.130881ms
dataSize:	1000	encrypt:	71.092815ms
dataSize:	1000	homoAdd:	5.715063ms
dataSize:	1000	decrypt:	3.929744ms
-----------------
dataSize:	10000	key gen:	134.052824ms
dataSize:	10000	encrypt:	979.068918ms
dataSize:	10000	homoAdd:	57.588404ms
dataSize:	10000	decrypt:	3.519321ms
-----------------
dataSize:	100000	key gen:	200.993502ms
dataSize:	100000	encrypt:	12.489329647s
dataSize:	100000	homoAdd:	561.569553ms
dataSize:	100000	decrypt:	3.568998ms
```

In conclusion, simple OU implementation in Go already provides acceptable performance. If we want to compute sum over 1M numbers over OU, it takes about 120s to encrypt and 5s to add. These numbers can be improved if we

1. Move the implementation to C/C++.
1. Use multi-threading to compute encryption/addition in parallel.
