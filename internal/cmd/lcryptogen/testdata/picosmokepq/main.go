// Command picosmokepq exercises the post-quantum lcrypto key exchanges so that
// TinyGo's -print-allocs reports each heap allocation site reachable from them.
// ML-KEM works on 512 byte polynomials by value: it needs -stack-size=16KB, at
// which TinyGo keeps allocations of up to 1 KiB on the stack.
package main

import (
	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/mlkem"
	"github.com/soypat/lcrypto/x25519mlkem768"
)

var (
	mClient, mServer mlkem.Exchanger768
	hClient, hServer x25519mlkem768.Exchanger

	cs     [x25519mlkem768.ClientShareSize]byte
	ss     [x25519mlkem768.ServerShareSize]byte
	shared [2][x25519mlkem768.SharedSize]byte
)

// counter is a deterministic entropy source; real firmware reads a TRNG.
type counter struct{ n byte }

func (r *counter) Read(b []byte) (int, error) {
	for i := range b {
		r.n++
		b[i] = r.n
	}
	return len(b), nil
}

var rand counter

func main() {
	println(exchange(&mClient, &mServer), exchange(&hClient, &hServer))
}

func exchange(client, server lcrypto.Exchanger) bool {
	n, err := client.ClientGenerateRekey(cs[:], &rand)
	if err != nil {
		return false
	}
	nss, nShared, err := server.ServerSharedRekey(ss[:], shared[0][:], cs[:n], &rand)
	if err != nil {
		return false
	}
	if _, err = client.ClientShared(shared[1][:], ss[:nss]); err != nil {
		return false
	}
	client.Zeroize()
	server.Zeroize()
	return string(shared[0][:nShared]) == string(shared[1][:nShared])
}
