//go:build armbe || arm64be || m68k || mips || mips64 || mips64p32 || ppc || ppc64 || s390 || s390x || shbe || sparc || sparc64

package cpu

// BigEndian is a constant so that big-endian code paths compile away.
const BigEndian = true
