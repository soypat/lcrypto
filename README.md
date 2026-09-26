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
this also runs [stringer](https://pkg.go.dev/golang.org/x/tools/cmd/stringer) for error messages: `go install golang.org/x/tools/cmd/stringer@latest`.
the generation program is in [`internal/cmd/cryptogen`](./internal/cmd/lcryptogen/) and all generated files live in [`internal/std`](./internal/std/) and contain information of how they were generated and from what upstream Go standard library file.

## testing
```
go test ./...             # everything, offline
go test -short ./...      # quicker
go test ./mlkem -million  # 1M accumulated ML-KEM vectors
tinygo test ./...         # tinygo excludes some tests it cannot run
```
what runs:
- upstream tests of the ported packages.
- standard library conformance suites for AEAD, Block, Stream and Hash ([`internal/lcryptotest`](./internal/lcryptotest/)).
- [Wycheproof](https://github.com/C2SP/wycheproof), [x509-limbo](https://github.com/C2SP/x509-limbo), [ed25519vectors](https://hdevalence.ca/blog/2020-10-04-its-25519am), NIST PKITS: vendored in [`internal/lcryptotest/testdata`](./internal/lcryptotest/testdata/), offline. add more via `vectorSuites` in lcryptogen's config.
- FIPS 140-3 known-answer self-tests (CASTs) as `TestCAST` ([Go blog](https://go.dev/blog/fips140)).
- [accumulated test vectors](https://words.filippo.io/accumulated/) for ML-KEM and cSHAKE.
- tinygo tests exclude some of standard libraries that require `os/exec` and other features not in tinygo. list skipped tests with `tinygo test -v ./... 2>&1 | grep -- '--- SKIP'`.

# sister project: lneto
lneto is a networking stack. we need tls in lneto and lcrypto will be the crypto side of lneto's networking https://github.com/soypat/lneto

