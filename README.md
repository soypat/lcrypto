# lcrypto

delicious, heapless, unaudited cryptographic algorithms based on the Go standard library

the Go standard library is fantabulous but not great on microcontrollers

i want a Go standard library for use on microcontrollers

ergo: lcrypto.

## you can't be serious

yes.

## you can't do that

relax, its fine. what i did was generate it based off the standard library so it's mostly ok

## you used an llm for that

yes... and no. i used an llm to generate a program that parses the standard library and using a few rewrite-rules it translates the tried and tested standard library algorithms to heapless versions. so it is deterministically based on the standard library, unlike just asking an llm to rewrite it.

## i like determinism

yes. determinism is good. the result is only as good as the rewrite program and standard library, so we'll get better with time, and likely only better. 

however, not all is roses for all you purists. we are in process of defining brand new abstractions for the crypto algorithms we know and love. see [`lcrypto.go`](./lcrypto.go) for a list of interfaces.

## oh dear, here we go...

i swear i can do better than the standard library! my mother says im really smart!

# developing
generate files and print names of generated files with 
```
go generate -v ./...
```
the generation program is in [`internal/cmd/cryptogen`](./internal/cmd/lcryptogen/) and all generated files live in [`internal/std`](./internal/std/) and contain information of how they were generated and from what upstream Go standard library file.

## testing
```
go test ./...                    # everything, fetching Wycheproof, x509-limbo and ed25519vectors with the go command
go test -short ./...             # offline and quick
LCRYPTO_OFFLINE=1 go test ./...  # offline, full length
go test ./mlkem -million         # 1M accumulated ML-KEM vectors
tinygo test ./x509               # external suites skip under TinyGo
```
the standard library's test helpers (`crypto/internal/cryptotest`, its Wycheproof and x509-limbo schemas) are also ported by lcryptogen, into [`internal/lcryptotest`](./internal/lcryptotest/).

# sister project: lneto
lneto is a networking stack. we need tls in lneto and lcrypto will be the crypto side of lneto https://github.com/soypat/lneto

