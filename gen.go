package lcrypto

// Generation is reproducible from a clean checkout: fetch recreates the gitignored
// inputs local/_go and local/_x from the pinned Go toolchain and x/crypto module
// (downloaded to the module cache if missing), checked against manifest.txt by
// the generator.
//go:generate go run ./internal/cmd/lcryptogen fetch
//go:generate go run ./internal/cmd/lcryptogen generate
