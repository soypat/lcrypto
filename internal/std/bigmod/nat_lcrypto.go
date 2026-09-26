package bigmod

import "errors"

// errNatTooLarge is the panic value of growing a Nat past preallocTarget bits.
// Callers bound the sizes of their inputs, e.g. of RSA moduli, before using bigmod.
var errNatTooLarge = errors.New("bigmod: number larger than 4096 bits")

// MaxBits is the size in bits of the largest number a Nat can hold.
const MaxBits = preallocTarget
