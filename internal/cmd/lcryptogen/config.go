package main

import "strings"

// Pinned inputs. Changing these requires `lcryptogen fetch` then `lcryptogen -update-manifest generate`.
const (
	goVersion      = "go1.27.1"
	xcryptoVersion = "v0.57.0"
	modulePath     = "github.com/soypat/lcrypto"
	stdDir         = "internal/std"         // Output root, relative to module root.
	kitDir         = "internal/lcryptotest" // Output root of Kit packages.
	vectorsDir     = "local/_vectors"       // Fetched test vector suites.
)

// pkgSpec describes one ported package.
type pkgSpec struct {
	// Src is "go:<path under GOROOT/src>" or "x:<path under golang.org/x/crypto>".
	Src string
	// Dst is the output directory relative to internal/std.
	Dst string
	// DropFiles are base names of source files not ported.
	DropFiles []string
	// DropDecls are top-level declarations removed from every ported file: "Name" or "Recv.Name".
	// Each must match at least once so that upstream renames are noticed.
	DropDecls []string
	// Patches are exact text replacements applied before the generic rules.
	Patches []patch
	// KeepDecls, when set, keeps only these top-level declarations ("Name" or
	// "Recv.Name") and drops the rest, for packages of which little is wanted.
	KeepDecls []string
	// Name renames the package, i.e. when Dst differs from the upstream name.
	Name string
	// NoTests skips porting _test.go files.
	NoTests bool
	// Kit ports test support code to kitDir/Dst rather than stdDir/Dst: build
	// constraints are kept, imports of non-internal std packages are allowed and
	// the allocation rules are skipped.
	Kit bool
	// Threads add a parameter to helper functions, see [pkgState.threadParams].
	Threads []thread
	// Hoists move locals into struct scratch space, see [pkgState.hoistLocals].
	Hoists []hoist
	// FieldArrays turn slice fields into fixed arrays, see [rewriter.fieldArrays].
	FieldArrays []fieldArray
	// ValueFields are struct types whose pointer fields become value fields, see
	// [typedState.valueFields].
	ValueFields []string
	// Decls are declarations added to the package, i.e. a struct that Threads pass
	// and Hoists fill with scratch space.
	Decls []string
}

// fieldArray turns slice field Field of struct Type into an array of Len
// elements and a length field LenField: storage moves inside the struct, so
// values no longer need a separate heap allocation. Reads go through the
// generated accessor Accessor, which returns the slice view.
type fieldArray struct {
	Type, Field, Elem, Len, LenField, Accessor string
}

// thread adds Param (i.e. "g *GCM") first to each function of Funcs and passes its
// name at every call site in the package.
type thread struct {
	Funcs []string
	Param string
}

// hoist moves the local variables Vars of Func into scratch fields of struct Type,
// reached through the pointer Via in scope. A var is "name" or "name:field". Functions
// hoisting the same field name must never run nested.
type hoist struct {
	Func, Via, Type string
	Vars            []string
}

// patch replaces Old with New inside File, scoped to declaration Decl when set.
// Old must occur exactly Count times (1 when zero) within the scope.
type patch struct {
	File     string
	Decl     string
	Old, New string
	Count    int
}

// importMap maps upstream import paths to their port under internal/std.
// Paths absent here are either allowed std packages or a hard error.
var importMap = map[string]string{
	"internal/byteorder":                         "byteorder",
	"crypto/internal/fips140deps/byteorder":      "byteorder",
	"crypto/internal/constanttime":               "constanttime",
	"crypto/internal/fips140/alias":              "alias",
	"golang.org/x/crypto/internal/alias":         "alias",
	"crypto/internal/fips140/subtle":             "subtle",
	"crypto/internal/fips140/aes":                "aes",
	"crypto/internal/fips140/aes/gcm":            "gcm",
	"crypto/internal/fips140/sha256":             "sha256",
	"crypto/internal/fips140/sha512":             "sha512",
	"golang.org/x/crypto/chacha20":               "chacha20",
	"golang.org/x/crypto/internal/poly1305":      "poly1305",
	"golang.org/x/crypto/chacha20poly1305":       "chacha20poly1305",
	"crypto/internal/fips140deps/cpu":            "cpu", // Hand-written.
	"crypto/internal/fips140/sha3":               "sha3",
	"crypto/internal/fips140/mlkem":              "mlkem",
	"crypto/internal/fips140/edwards25519/field": "field",
	"crypto/internal/fips140/edwards25519":       "edwards25519",
	"crypto/internal/fips140/ed25519":            "ed25519",
	"crypto/internal/fips140/nistec":             "nistec",
	"crypto/internal/fips140/nistec/fiat":        "fiat",
	"golang.org/x/crypto/cryptobyte":             "cryptobyte",
	"crypto/internal/fips140/bigmod":             "bigmod",
	"crypto/internal/fips140/rsa":                "rsa",
	"golang.org/x/crypto/cryptobyte/asn1":        "cryptobyte/asn1",
}

// kitImportMap maps upstream test support imports, allowed in tests and Kit
// packages only, to module-relative paths.
var kitImportMap = map[string]string{
	"internal/testenv":                      kitDir + "/testenv", // Hand-written.
	"internal/race":                         kitDir + "/testenv",
	"internal/msan":                         kitDir + "/testenv",
	"internal/asan":                         kitDir + "/testenv",
	"internal/testhash":                     kitDir + "/testhash",
	"testing/quick":                         kitDir + "/quick", // Hand-written: runs under TinyGo.
	"crypto/internal/cryptotest":            kitDir + "/cryptotest",
	"crypto/internal/cryptotest/wycheproof": kitDir + "/wycheproof",
	"crypto/internal/cryptotest/x509limbo":  kitDir + "/x509limbo",
}

// dir is the spec's output directory relative to the module root.
func (s *pkgSpec) dir() string {
	if s.Kit {
		return kitDir + "/" + s.Dst
	}
	return stdDir + "/" + s.Dst
}

// importMapNonTest applies to non-test files only; tests may use the real std package.
var importMapNonTest = map[string]string{
	"crypto/subtle": "subtle",
}

// allowedStd are the std imports generated non-test code may keep.
var allowedStd = map[string]bool{
	"bytes":           true,
	"encoding/binary": true,
	"errors":          true,
	"hash":            true,
	"math":            true,
	"math/bits":       true,
	"runtime":         true,
	"strconv":         true,
	"unsafe":          true,
}

// dropAlways lists declarations removed wherever found (not required to match).
var dropAlways = []string{
	"checkGenericIsExpected", // Asserts asm/generic selection for FIPS.
	"fipsSelfTest",
	"fips140Enforced",
}

// Calls removed as statements: FIPS service indicators, self tests and impl registration.
var stripCalls = map[string]bool{
	"fips140.RecordApproved":    true,
	"fips140.RecordNonApproved": true,
	"fips140.CAST":              true,
	"fips140.PCT":               true,
	"impl.Register":             true,
	"fipsSelfTest":              true,
	"checkGenericIsExpected":    true,
	// Test support: the port is always the latest module.
	"MustMinimumFIPS140ModuleVersion": true,
}

// Blank imports removed with FIPS: the module integrity self-check.
var stripImports = map[string]bool{"crypto/internal/fips140/check": true}

// Conditions known false once FIPS is stripped; `if <cond> {...}` without else is removed.
var falseConds = map[string]bool{
	"fips140Enforced()":  true,
	"fips140.Enforced()": true,
	"fips140.Enabled":    true,
	"boring.Enabled":     true, // BoringCrypto, in test support code.
}

var hashMarshal = []string{"Digest.MarshalBinary", "Digest.AppendBinary", "Digest.UnmarshalBinary", "Digest.Clone", "consumeUint64"}

// packages is processed in order; order also fixes output determinism.

// vectorSuite is a test vector suite that lcryptogen vendors, gzipped, into
// kitDir/testdata so that tests run offline and under TinyGo: from module
// Module at Version, or from testdata of the pinned Go tree at Src.
// cryptotest.Vectors reads back file F of kitDir/testdata/Dir/F.gz; with
// Archive, cryptotest.VectorFS reads kitDir/testdata/Dir.tar.gz.
type vectorSuite struct {
	Module, Version string
	// Pin, when set, is an upstream source that must quote Version: the
	// version the ported schema of the suite was generated against.
	Pin     string
	Src     string // "go:<path under GOROOT/src>", instead of Module.
	Dir     string
	Files   []string // Paths within the module or Src; globs for Src.
	Archive bool     // One tar of Files, for suites of many files.
}

// vectorSuites are fetched into local/_vectors/Dir. Tests read only the files
// listed: add a file here to use it.
var vectorSuites = []vectorSuite{
	{
		Module: "github.com/c2sp/wycheproof", Version: "v0.0.0-20260625212325-ee7b4f7e6119",
		Pin: "go:crypto/internal/cryptotest/wycheproof/schemaversion.go", Dir: "wycheproof",
		Files: prefixed("testvectors_v1/",
			"aes_gcm_test.json", "chacha20_poly1305_test.json",
			"x25519_test.json", "ecdh_secp256r1_ecpoint_test.json",
			"ecdsa_secp256r1_sha256_test.json", "ecdsa_secp256r1_sha512_test.json",
			"ecdsa_secp256r1_sha3_256_test.json", "ecdsa_secp256r1_sha3_512_test.json",
			"ecdsa_secp384r1_sha256_test.json", "ecdsa_secp384r1_sha384_test.json", "ecdsa_secp384r1_sha512_test.json",
			"ecdsa_secp384r1_sha3_384_test.json", "ecdsa_secp384r1_sha3_512_test.json",
			"ed25519_test.json",
			"rsa_signature_2048_sha256_test.json", "rsa_signature_2048_sha384_test.json", "rsa_signature_2048_sha512_test.json",
			"rsa_signature_3072_sha256_test.json", "rsa_signature_3072_sha384_test.json", "rsa_signature_3072_sha512_test.json",
			"rsa_signature_4096_sha256_test.json", "rsa_signature_4096_sha384_test.json", "rsa_signature_4096_sha512_test.json",
			"rsa_pss_2048_sha256_mgf1_32_test.json", "rsa_pss_2048_sha384_mgf1_48_test.json",
			"rsa_pss_3072_sha256_mgf1_32_test.json", "rsa_pss_4096_sha256_mgf1_32_test.json",
			"rsa_pss_4096_sha384_mgf1_48_test.json", "rsa_pss_4096_sha512_mgf1_64_test.json", "rsa_pss_misc_test.json",
			"mlkem_768_keygen_seed_test.json", "mlkem_768_encaps_test.json", "mlkem_768_test.json",
		),
	},
	{
		Module: "github.com/C2SP/x509-limbo", Version: "v0.0.0-20260522003327-feb7caccc1af",
		Pin: "go:crypto/internal/cryptotest/x509limbo/schemaversion.go", Dir: "x509limbo",
		Files: []string{"limbo.json"},
	},
	{
		// NIST PKITS and policy certificates, for x509's differential tests.
		Src: "go:crypto/x509/testdata", Dir: "x509", Archive: true,
		Files: []string{"*.pem", "nist-pkits/vectors.json", "nist-pkits/certs/*.crt"},
	},
	{
		// crypto/ed25519's TestSignAgainstVectors input.
		Src: "go:crypto/ed25519/testdata", Dir: "ed25519", Files: []string{"sign.input.gz"},
	},
	{
		// As pinned by crypto/ed25519's TestEd25519Vectors.
		Module: "filippo.io/mostly-harmless/ed25519vectors", Version: "v0.0.0-20210322192420-30a2d7243a94",
		Pin: "go:crypto/ed25519/ed25519vectors_test.go", Dir: "ed25519vectors",
		Files: []string{"ed25519vectors.json"},
	},
}

func prefixed(prefix string, names ...string) []string {
	for i, n := range names {
		names[i] = prefix + n
	}
	return names
}

var packages = []pkgSpec{
	{Src: "go:internal/byteorder", Dst: "byteorder"},
	{
		Src: "go:crypto/internal/constanttime", Dst: "constanttime",
		Patches: []patch{{
			// Compiler intrinsic in std; Go bools are stored as 0 or 1, so reading the byte is branch free.
			File: "constant_time.go", Decl: "boolToUint8",
			Old: `panic("unreachable; must be intrinsicified")`,
			New: `return *(*uint8)(unsafe.Pointer(&b))`,
		}},
	},
	{Src: "go:crypto/internal/fips140/alias", Dst: "alias"},
	{Src: "go:crypto/internal/fips140/subtle", Dst: "subtle"},
	{
		Src: "go:crypto/internal/fips140/aes", Dst: "aes",
		DropFiles: []string{"cbc*.go", "ctr*.go", "interface_test.go"},
		Patches: []patch{
			// CBC is not ported: one block of it is the block cipher of plaintext XOR IV.
			{
				File: "cast.go", Old: "NewCBCEncrypter(b, iv).CryptBlocks(buf, plaintext)",
				New: "for i := range buf {\n\t\t\tbuf[i] = plaintext[i] ^ iv[i]\n\t\t}\n\t\tb.Encrypt(buf, buf)",
			},
			{
				File: "cast.go", Old: "NewCBCDecrypter(b, iv).CryptBlocks(buf, ciphertext)",
				New: "b.Decrypt(buf, ciphertext)\n\t\tfor i := range buf {\n\t\t\tbuf[i] ^= iv[i]\n\t\t}",
			},
		},
	},
	{
		Src: "go:crypto/internal/fips140/aes/gcm", Dst: "gcm",
		DropFiles: []string{"cast.go", "cmac.go", "ctrkdf.go", "gcm_nonces.go"}, // The CAST is of the counter KDF.
		DropDecls: []string{"GHASH"},                                            // Returns an escaping slice.
		Patches: []patch{
			// Range-over-func iterator: its closure and captured state are heap allocated by TinyGo.
			{
				File: "ghash.go", Decl: "ghash",
				Old: ghashIterator,
				New: `for _, input := range inputs {
		for len(input) > 0 {
			var block []byte
			if len(input) >= gcmBlockSize {
				block, input = input[:gcmBlockSize], input[gcmBlockSize:]
			} else {
				var partialBlock [gcmBlockSize]byte
				copy(partialBlock[:], input)
				block, input = partialBlock[:], nil
			}`,
			},
			{
				// File scope: the previous patch leaves ghash unparsable until this closes the loops.
				File: "ghash.go",
				Old:  "uint32(z[3]), uint32(z[3]>>32)\n\t}\n",
				New:  "uint32(z[3]), uint32(z[3]>>32)\n\t}\n\t}\n",
			},
		},
		Threads: []thread{{
			Funcs: []string{"deriveCounterGeneric", "gcmCounterCryptGeneric", "gcmAuthGeneric", "ghash"},
			Param: "g *GCM",
		}},
		Hoists: []hoist{
			{Func: "sealGeneric", Via: "g", Type: "GCM", Vars: []string{"H", "counter", "tagMask", "tag"}},
			{Func: "openGeneric", Via: "g", Type: "GCM", Vars: []string{"H", "counter", "tagMask", "expectedTag:tag"}},
			{Func: "deriveCounterGeneric", Via: "g", Type: "GCM", Vars: []string{"lenBlockArr:lenBlock"}},
			{Func: "gcmAuthGeneric", Via: "g", Type: "GCM", Vars: []string{"lenBlockArr:lenBlock", "S"}},
			{Func: "gcmCounterCryptGeneric", Via: "g", Type: "GCM", Vars: []string{"mask"}},
			{Func: "ghash", Via: "g", Type: "GCM", Vars: []string{"partialBlock"}},
		},
	},
	{
		Src: "go:crypto/internal/fips140/sha256", Dst: "sha256",
		DropDecls: append([]string{"consumeUint32"}, hashMarshal...),
		Hoists:    []hoist{{Func: "Digest.checkSum", Via: "d", Type: "Digest", Vars: []string{"tmp:pad"}}},
		Patches: []patch{{
			// Save and restore the mutable state instead of copying the whole Digest,
			// which TinyGo heap allocates.
			File: "sha256.go", Decl: "Digest.Sum",
			Old: "d0 := *d\n\thash := d0.checkSum()\n\tif d0.is224 {",
			New: "h, x, nx, n := d.h, d.x, d.nx, d.len\n\thash := d.checkSum()\n\td.h, d.x, d.nx, d.len = h, x, nx, n\n\tif d.is224 {",
		}},
	},
	{
		Src: "go:crypto/internal/fips140/sha512", Dst: "sha512",
		DropDecls: hashMarshal,
		Patches: []patch{{
			// See sha256: the Digest copy is heap allocated, and over TinyGo's stack limit.
			File: "sha512.go", Decl: "Digest.Sum",
			Old: "d0 := new(Digest)\n\t*d0 = *d\n\thash := d0.checkSum()",
			New: "h, x, nx, n := d.h, d.x, d.nx, d.len\n\thash := d.checkSum()\n\td.h, d.x, d.nx, d.len = h, x, nx, n",
		}},
		Hoists: []hoist{
			{Func: "Digest.checkSum", Via: "d", Type: "Digest", Vars: []string{"tmp:pad"}},
			{Func: "blockGeneric", Via: "dig", Type: "Digest", Vars: []string{"w"}}, // 640 bytes: beyond TinyGo's stack allocation limit.
		},
	},
	{
		Src: "go:crypto/internal/fips140/sha3", Dst: "sha3",
		DropDecls: []string{
			"Digest.Clone", "Digest.MarshalBinary", "Digest.AppendBinary", "Digest.UnmarshalBinary",
			"SHAKE.Clone", "SHAKE.MarshalBinary", "SHAKE.AppendBinary", "SHAKE.UnmarshalBinary",
		},
		Patches: []patch{
			{
				// Clone heap allocates; the copy is only read from.
				File: "sha3.go", Decl: "Digest.sumGeneric",
				Old: "dup := d.Clone()", New: "dup := *d",
			},
			{
				// The big-endian branch's defer closure keeps TinyGo from proving da does not
				// escape, heap allocating every Digest. Split the permutation over words out and
				// convert explicitly on big-endian targets instead.
				File: "keccakf.go", Decl: "keccakF1600Generic",
				Old: keccakPrologue,
				New: `if cpu.BigEndian {
		var a [25]uint64
		for i := range a {
			a[i] = byteorder.LEUint64(da[i*8:])
		}
		keccakF1600Words(&a)
		for i := range a {
			byteorder.LEPutUint64(da[i*8:], a[i])
		}
		return
	}
	keccakF1600Words((*[25]uint64)(unsafe.Pointer(da)))
}

// keccakF1600Words applies the Keccak permutation to native-endian words.
func keccakF1600Words(a *[25]uint64) {`,
			},
		},
	},
	{
		Src: "go:crypto/internal/fips140/mlkem", Dst: "mlkem",
		DropFiles: []string{"mlkem1024.go"},
		DropDecls: []string{
			// DRBG-backed and test-only entry points; lcrypto draws randomness from the caller.
			"GenerateKey768", "generateKey", "TestingOnlyNewDecapsulationKey768", "TestingOnlyExpandedBytes768",
			"kemPCT", "EncapsulationKey768.Encapsulate", "EncapsulationKey768.encapsulate",
		},
		Patches: []patch{
			{
				// EncapsulationKey copies both keys' matrices to the heap only to encode t and ρ.
				File: "mlkem768.go", Decl: "kemKeyGen",
				Old: "ek := dk.EncapsulationKey().Bytes()",
				New: "ek := dk.encapsulationKeyBytes(make([]byte, 0, EncapsulationKeySize768))",
			},
			{File: "mlkem768.go", Decl: "kemEncaps", Old: "G := g.Sum(nil)", New: "G := g.Sum(make([]byte, 0, 64))"},
			{
				File: "mlkem768.go", Decl: "pkeDecrypt",
				Old: "return ringCompressAndEncode1(nil, w)",
				New: "return ringCompressAndEncode1(make([]byte, 0, encodingSize1), w)",
			},
		},
		Hoists: []hoist{
			{Func: "kemKeyGen", Via: "dk", Type: "DecapsulationKey768", Vars: []string{"GArr:G", "eArr:e", "ekArr:ek"}},
			{Func: "kemDecaps", Via: "dk", Type: "DecapsulationKey768", Vars: []string{"GArr:G", "KoutArr:K", "cc"}},
			{Func: "kemEncaps", Via: "ek", Type: "EncapsulationKey768", Vars: []string{"GArr:G"}},
			{Func: "pkeEncrypt", Via: "ex", Type: "encryptionKey", Vars: []string{"rArr:r", "e1Arr:e1", "uArr:u"}},
			{Func: "pkeDecrypt", Via: "dx", Type: "decryptionKey", Vars: []string{"uArr:u", "retArr:m"}},
		},
	},
	{Src: "go:crypto/internal/fips140/edwards25519/field", Dst: "field"},
	{
		// The precomputed base point tables, 30 KiB for constant time and 7.5 KiB
		// for variable time multiplication, do not fit a microcontroller: the base
		// point is multiplied like any other, with window tables the caller
		// provides, as for P-256 and P-384.
		Src: "go:crypto/internal/fips140/edwards25519", Dst: "edwards25519",
		NoTests:   true, // They exercise the dropped tables.
		DropDecls: []string{"basepointTable", "basepointTablePrecomp", "basepointNafTable", "basepointNafTablePrecomp", "Point.scalarBaseMultPrecomp"},
		Patches: []patch{
			// Variadic arguments are heap allocated by TinyGo.
			{
				File: "edwards25519.go",
				Old:  "func checkInitialized(points ...*Point) {\n\tfor _, p := range points {\n\t\tif p.x == (field.Element{}) && p.y == (field.Element{}) {\n\t\t\tpanic(\"edwards25519: use of uninitialized Point\")\n\t\t}\n\t}\n}",
				New:  "func checkInitialized(p *Point) {\n\tif p.x == (field.Element{}) && p.y == (field.Element{}) {\n\t\tpanic(\"edwards25519: use of uninitialized Point\")\n\t}\n}",
			},
			{File: "edwards25519.go", Old: "checkInitialized(p, q)", New: "checkInitialized(p)\n\tcheckInitialized(q)", Count: 2},
			{File: "edwards25519.go", Old: "checkInitialized(v, u)", New: "checkInitialized(v)\n\tcheckInitialized(u)"},
			{
				File: "scalarmult.go",
				Old:  "func (v *Point) ScalarBaseMult(x *Scalar) *Point {\n\tbasepointTable := basepointTable()",
				New: "func (v *Point) ScalarBaseMult(x *Scalar) *Point {\n\treturn v.scalarMult(x, generator, new(projLookupTable))\n}\n\n" +
					"func (v *Point) scalarBaseMultPrecomp(x *Scalar) *Point {\n\tbasepointTable := basepointTable()",
			},
			{
				File: "scalarmult.go",
				Old:  "func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {\n\tcheckInitialized(q)\n\n\tvar table projLookupTable\n\ttable.FromP3(q)",
				New: "func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {\n\treturn v.scalarMult(x, q, new(projLookupTable))\n}\n\n" +
					"// scalarMult is ScalarMult with the caller's table memory, which it overwrites.\n" +
					"func (v *Point) scalarMult(x *Scalar, q *Point, table *projLookupTable) *Point {\n\tcheckInitialized(q)\n\n\ttable.FromP3(q)",
			},
			{
				File: "scalarmult.go",
				Old:  "func (v *Point) VarTimeDoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar) *Point {",
				New: "func (v *Point) VarTimeDoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar) *Point {\n\treturn v.varTimeDoubleScalarBaseMult(a, A, b, new(nafLookupTable5), new(nafLookupTable5))\n}\n\n" +
					"// varTimeDoubleScalarBaseMult is VarTimeDoubleScalarBaseMult with the caller's\n" +
					"// table memory, which it overwrites. The base point gets a width 5 table too.\n" +
					"func (v *Point) varTimeDoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar, aTable, bTable *nafLookupTable5) *Point {",
			},
			{
				File: "scalarmult.go",
				Old: "\tbasepointNafTable := basepointNafTable()\n\tvar aTable nafLookupTable5\n\taTable.FromP3(A)\n" +
					"\t// Because the basepoint is fixed, we can use a wider NAF\n\t// corresponding to a bigger table.\n" +
					"\taNaf := a.nonAdjacentForm(5)\n\tbNaf := b.nonAdjacentForm(8)",
				New: "\taTable.FromP3(A)\n\tbTable.FromP3(generator)\n\taNaf := a.nonAdjacentForm(5)\n\tbNaf := b.nonAdjacentForm(5)",
			},
			{File: "scalarmult.go", Old: "multB := &affineCached{}", New: "multB := &projCached{}"},
			{File: "scalarmult.go", Old: "basepointNafTable.SelectInto(multB, bNaf[i])\n\t\t\ttmp1.AddAffine(v, multB)", New: "bTable.SelectInto(multB, bNaf[i])\n\t\t\ttmp1.Add(v, multB)"},
			{File: "scalarmult.go", Old: "basepointNafTable.SelectInto(multB, -bNaf[i])\n\t\t\ttmp1.SubAffine(v, multB)", New: "bTable.SelectInto(multB, -bNaf[i])\n\t\t\ttmp1.Sub(v, multB)"},
		},
	},
	{
		// Pure Ed25519 (RFC 8032). Keys carry the window tables of the base point
		// multiplications, which edwards25519 takes from its callers.
		Src: "go:crypto/internal/fips140/ed25519", Dst: "ed25519",
		DropDecls: []string{"fipsPCT", "pairwiseTest"}, // Pairwise consistency test of key generation, which is not ported.
		KeepDecls: []string{
			"seedSize", "publicKeySize", "privateKeySize", "signatureSize", "sha512Size",
			"PrivateKey", "PublicKey", "newPrivateKeyFromSeed", "precomputePrivateKey", "newPublicKey",
			"domPrefixPure", "sign", "signWithDom", "verify", "verifyWithDom",
		},
		Patches: []patch{
			{File: "cast.go", Old: "NewPublicKey(k.PublicKey())", New: "newPublicKey(new(PublicKey), k.PublicKeyBytes()[:])", Count: 2},
			{File: "ed25519.go", Old: "\tprefix [sha512Size / 2]byte\n", New: "\tprefix [sha512Size / 2]byte\n\tsc     edwards25519.Scratch\n"},
			{File: "ed25519.go", Old: "\taBytes [32]byte\n", New: "\taBytes [32]byte\n\tsc     edwards25519.Scratch\n"},
			{File: "ed25519.go", Old: "(&edwards25519.Point{}).ScalarBaseMult(s)", New: "(&edwards25519.Point{}).ScalarBaseMultScratch(s, &priv.sc)"},
			{File: "ed25519.go", Old: "(&edwards25519.Point{}).ScalarBaseMult(r)", New: "(&edwards25519.Point{}).ScalarBaseMultScratch(r, &priv.sc)"},
			{File: "ed25519.go", Old: "VarTimeDoubleScalarBaseMult(k, minusA, S)", New: "VarTimeDoubleScalarBaseMultScratch(k, minusA, S, &pub.sc)"},
		},
		// A Digest is 1000 bytes and Sum returns the buffer it is given: into the
		// keys, one digest and buffer for the hashes computed one after another.
		Hoists: []hoist{
			{Func: "precomputePrivateKey", Via: "priv", Type: "PrivateKey", Vars: []string{"hsObj:h", "hArr:digest"}},
			{Func: "signWithDom", Via: "priv", Type: "PrivateKey", Vars: []string{"mhObj:h", "messageDigestArr:digest", "khObj:h", "hramDigestArr:digest"}},
			{Func: "verifyWithDom", Via: "pub", Type: "PublicKey", Vars: []string{"khObj:h", "hramDigestArr:digest"}},
		},
	},
	{
		Src: "go:crypto/internal/fips140/nistec/fiat", Dst: "fiat",
		DropFiles: []string{"cast.go", "p224*.go", "p521*.go", "benchmark_test.go"}, // cast.go only imports the integrity check.
	},
	{
		Src: "go:crypto/internal/fips140/nistec", Dst: "nistec",
		DropFiles: []string{"p224*.go", "p521.go", "benchmark_test.go"},
		// The 207 KiB P-384 generator table does not fit a microcontroller:
		// multiply the generator with ScalarMult instead.
		DropDecls:   []string{"p384GeneratorTable", "p384GeneratorTableOnce", "P384Point.generatorTable", "P384Point.ScalarBaseMult"},
		ValueFields: []string{"P384Point"},
		Patches: append(append(
			lazyCurveB("p256", "0x27, 0xd2, 0x60, 0x4b"),
			lazyCurveB("p384", "0xed, 0xd3, 0xec, 0x2a, 0xef")...),
			// The 1.5 KiB window table cannot be hoisted into P256Point, which it is made
			// of: take it as a parameter so callers can provide scratch space.
			patch{
				File: "p256.go", Decl: "P256Point.ScalarMult",
				Old: "func (p *P256Point) ScalarMult(q *P256Point, scalar []byte) (*P256Point, error) {",
				New: "func (p *P256Point) ScalarMult(q *P256Point, scalar []byte) (*P256Point, error) {\n\treturn p.scalarMult(q, scalar, new(p256Table))\n}\n\nfunc (p *P256Point) scalarMult(q *P256Point, scalar []byte, table *p256Table) (*P256Point, error) {",
			},
			patch{File: "p256.go", Old: "table := new(p256Table).Compute(q)", New: "table.Compute(q)"},
			// Likewise the 2 KiB P-384 table, which the ValueFields rule makes a value array.
			patch{
				File: "p384.go", Decl: "P384Point.ScalarMult",
				Old: "func (p *P384Point) ScalarMult(q *P384Point, scalar []byte) (*P384Point, error) {\n" +
					"\t// Compute a p384Table for the base point q. The explicit NewP384Point\n" +
					"\t// calls get inlined, letting the allocations live on the stack.\n" +
					"\tvar table = p384Table{NewP384Point(), NewP384Point(), NewP384Point(),\n" +
					"\t\tNewP384Point(), NewP384Point(), NewP384Point(), NewP384Point(),\n" +
					"\t\tNewP384Point(), NewP384Point(), NewP384Point(), NewP384Point(),\n" +
					"\t\tNewP384Point(), NewP384Point(), NewP384Point(), NewP384Point()}",
				New: "func (p *P384Point) ScalarMult(q *P384Point, scalar []byte) (*P384Point, error) {\n\treturn p.scalarMult(q, scalar, new(p384Table))\n}\n\n" +
					"// scalarMult is ScalarMult with the caller's table memory, which it overwrites.\n" +
					"func (p *P384Point) scalarMult(q *P384Point, scalar []byte, table *p384Table) (*P384Point, error) {",
			},
		),
	},
	{
		// Nat keeps its limbs in a fixed array sized for 4096 bit numbers, the largest
		// RSA modulus accepted: values carry their storage and never grow onto the heap.
		Src: "go:crypto/internal/fips140/bigmod", Dst: "bigmod",
		DropDecls: []string{"NewModulusProduct"}, // Key generation only.
		Patches: []patch{
			{File: "nat.go", Old: "const preallocTarget = 2048", New: "const preallocTarget = 4096"},
			{
				File: "nat.go", Decl: "NewNat",
				Old: "limbs := make([]uint, 0, preallocLimbs)\n\treturn &Nat{limbs}", New: "return &Nat{}",
			},
			{
				File: "nat.go", Decl: "Nat.expand",
				Old: "\t\tnewLimbs := make([]uint, n)\n\t\tcopy(newLimbs, x.limbs)\n\t\tx.limbs = newLimbs\n\t\treturn x\n",
				New: "\t\tpanic(errNatTooLarge)\n",
			},
			{
				File: "nat.go", Decl: "Nat.reset",
				Old: "\t\tx.limbs = make([]uint, n)\n\t\treturn x\n", New: "\t\tpanic(errNatTooLarge)\n",
			},
			// T holds 2n limbs and n never exceeds preallocLimbs.
			{
				File: "nat.go", Count: 2,
				Old: "\t\tif cap(T) < n*2 {\n\t\t\tT = make([]uint, 0, n*2)\n\t\t}\n", New: "",
			},
			// Size specializations exist for the assembly addMulVVW; in pure Go they
			// run the default loop and would need their own temporaries.
			{File: "nat.go", Decl: "Nat.montgomeryMul", Old: montgomeryMulSpecialized, New: ""},
			{File: "nat.go", Decl: "Nat.Mul", Old: mulSpecialized, New: ""},
			// Storage for the modulus itself, used by InitModulus.
			{
				File: "nat.go", Decl: "Modulus",
				Old: "\trr    *Nat // R*R for montgomeryRepresentation\n",
				New: "\trr    *Nat // R*R for montgomeryRepresentation\n\n\tnatStore Nat // nat of a Modulus set up by InitModulus.\n",
			},
		},
		FieldArrays: []fieldArray{{Type: "Nat", Field: "limbs", Elem: "uint", Len: "preallocLimbs", LenField: "nlimbs", Accessor: "lim"}},
		Hoists: []hoist{
			// The public key operation, m^e mod n: temporaries live in the Modulus.
			{Func: "rr", Via: "m", Type: "Modulus", Vars: []string{"rrObj:rr"}},
			{Func: "Nat.maybeSubtractModulus", Via: "m", Type: "Modulus", Vars: []string{"tObj:subModT"}},
			{Func: "Nat.Sub", Via: "m", Type: "Modulus", Vars: []string{"tObj:subT"}},
			{Func: "Nat.montgomeryReduction", Via: "m", Type: "Modulus", Vars: []string{"oneObj:one"}},
			{Func: "Nat.montgomeryMul", Via: "m", Type: "Modulus", Vars: []string{"TArr:T"}},
			{Func: "Nat.ExpShortVarTime", Via: "m", Type: "Modulus", Vars: []string{"xRObj:expX"}},
		},
	},
	{
		// RSA signature verification helpers; lcrypto composes them in rsa_lcrypto.go.
		Src: "go:crypto/internal/fips140/rsa", Dst: "rsa",
		DropFiles: []string{"cast.go", "keygen.go", "largeexponent.go"}, // The CAST signs, which is not ported.
		KeepDecls: []string{
			"PublicKey", "PublicKey.Size", "checkPublicKey", "ErrVerification", "ErrMessageTooLong",
			"hashPrefixes", "hashSize", "pkcs1v15ConstructEM",
			"incCounter", "mgf1XOR", "emsaPSSVerify", "pssSaltLengthAutodetect",
		},
		NoTests: true,
		Decls: []string{
			"// maxModulusBytes is the size of the largest modulus bigmod holds.\nconst maxModulusBytes = bigmod.MaxBits / 8",
			"// rsaScratch holds buffers that would otherwise escape through hash.Hash or be\n// heap allocated; lcryptogen hoists them here.\ntype rsaScratch struct{}",
		},
		Patches: []patch{
			{File: "pkcs1v15.go", Decl: "pkcs1v15ConstructEM", Old: "em := make([]byte, k)", New: "em := make([]byte, maxModulusBytes)[:k]"},
			{File: "pkcs1v22.go", Decl: "mgf1XOR", Old: "var digest []byte", New: "digest := make([]byte, 0, 64)"},
			{File: "pkcs1v22.go", Decl: "emsaPSSVerify", Old: "h0 := hash.Sum(nil)", New: "h0 := hash.Sum(make([]byte, 0, 64))"},
		},
		Threads: []thread{{Funcs: []string{"pkcs1v15ConstructEM", "emsaPSSVerify", "mgf1XOR"}, Param: "sc *rsaScratch"}},
		Hoists: []hoist{
			{Func: "pkcs1v15ConstructEM", Via: "sc", Type: "rsaScratch", Vars: []string{"emArr:em"}},
			{Func: "emsaPSSVerify", Via: "sc", Type: "rsaScratch", Vars: []string{"prefix", "h0Arr:h0"}},
			{Func: "mgf1XOR", Via: "sc", Type: "rsaScratch", Vars: []string{"counter", "digestArr:digest"}},
			// A copy of the modulus, only to check it is odd.
			{Func: "checkPublicKey", Via: "pub", Type: "PublicKey", Vars: []string{"natObj:nat"}},
		},
	},
	{Src: "x:cryptobyte/asn1", Dst: "cryptobyte/asn1"},
	{
		// Parsing half of cryptobyte. Building, and reading through reflect, math/big,
		// time or encoding/asn1 types, allocate.
		Src: "x:cryptobyte", Dst: "cryptobyte",
		DropFiles: []string{"builder.go"},
		DropDecls: []string{
			"Builder.AddASN1Int64", "Builder.AddASN1Int64WithTag", "Builder.AddASN1Enum", "Builder.addASN1Signed",
			"Builder.AddASN1Uint64", "Builder.AddASN1BigInt", "Builder.AddASN1OctetString", "Builder.AddASN1GeneralizedTime",
			"Builder.AddASN1UTCTime", "Builder.AddASN1BitString", "Builder.addBase128Int", "isValidOID",
			"Builder.AddASN1ObjectIdentifier", "Builder.AddASN1Boolean", "Builder.AddASN1NULL", "Builder.MarshalASN1", "Builder.AddASN1",
			"String.ReadASN1Integer", "String.readASN1BigInt", "bigOne", "String.ReadASN1ObjectIdentifier",
			"String.ReadASN1GeneralizedTime", "String.ReadASN1UTCTime", "String.ReadASN1BitString", "String.ReadOptionalASN1Integer",
		},
		NoTests: true, // Tests are written with the Builder.
	},
	{
		// Private key range checks of the NIST curves.
		Src: "go:crypto/internal/fips140/ecdh", Dst: "ecdh",
		KeepDecls: []string{"isZero", "isLess", "p256Order"},
		Patches: []patch{{
			// Only the P-256 order is ported.
			File: "order_test.go",
			Old:  "if !bytes.Equal(elliptic.P224().Params().N.Bytes(), P224().N) {\n\t\tt.Errorf(\"P-224 order mismatch\")\n\t}\n\t",
		}, {
			File: "order_test.go", Old: "P256().N", New: "p256Order",
		}, {
			File: "order_test.go",
			Old:  "\n\tif !bytes.Equal(elliptic.P384().Params().N.Bytes(), P384().N) {\n\t\tt.Errorf(\"P-384 order mismatch\")\n\t}\n\tif !bytes.Equal(elliptic.P521().Params().N.Bytes(), P521().N) {\n\t\tt.Errorf(\"P-521 order mismatch\")\n\t}",
		}, {
			// The CAST's key agreement, as p256.Exchanger computes it.
			File: "cast.go",
			Old:  "k := &PrivateKey{d: privateKey, pub: PublicKey{curve: p256}}\n\t\tpeer := &PublicKey{curve: p256, q: publicKey}\n\t\tgot, err := ecdh(P256(), k, peer)\n",
			New:  "var p nistec.P256Point\n\t\tvar s nistec.P256Scratch\n\t\tif _, err := p.SetBytes(publicKey); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif _, err := p.ScalarMultScratch(&p, privateKey, &s); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tgot, err := p.BytesX()\n",
		}},
	},
	{
		// X25519 of RFC 7748 from crypto/ecdh, less its allocating key types.
		Src: "go:crypto/ecdh", Dst: "x25519", Name: "x25519",
		DropFiles: []string{"ecdh.go", "nist.go"},
		KeepDecls: []string{"x25519ScalarMult"},
		Patches: []patch{{
			// Element.Bytes returns a slice of its own frame, which escapes.
			File: "x25519.go", Decl: "x25519ScalarMult",
			Old: "copy(dst[:], x2.Bytes())", New: "x2.BytesTo((*[32]byte)(dst))",
		}},
		NoTests: true,
	},
	{
		Src: "x:chacha20", Dst: "chacha20",
		Patches: []patch{{
			// Keeps crypto/cipher (and its init functions) out of the build.
			File: "chacha_generic.go", Old: "var _ cipher.Stream = (*Cipher)(nil)\n", New: "",
		}},
	},
	{
		Src: "x:internal/poly1305", Dst: "poly1305",
		DropDecls: []string{"Sum", "Verify"}, // Package-level helpers heap allocate a *MAC under TinyGo.
		NoTests:   true,                      // Tests exercise Sum/Verify.
	},
	{
		Src: "x:chacha20poly1305", Dst: "chacha20poly1305",
		DropFiles: []string{"fips140only_compat.go", "fips140only_go1.26.go"},
		Patches: []patch{
			// Keeps crypto/cipher out of non-test code; *chacha20poly1305 still satisfies cipher.AEAD.
			{
				File: "chacha20poly1305.go", Decl: "New",
				Old: "(cipher.AEAD, error)", New: "(*chacha20poly1305, error)",
			},
			{
				File: "xchacha20poly1305.go", Decl: "NewX",
				Old: "(cipher.AEAD, error)", New: "(*xchacha20poly1305, error)",
			},
			// Stream, MAC and one-time key live in the struct: no per-record construction.
			{
				File: "chacha20poly1305.go", Decl: "chacha20poly1305",
				Old: "key [KeySize]byte",
				New: "key     [KeySize]byte\n\tstream  chacha20.Cipher\n\tmac     poly1305.MAC\n\tpolyKey [32]byte",
			},
			{
				File: "chacha20poly1305_generic.go", Count: 2,
				Old: "var polyKey [32]byte",
				New: "polyKey := &c.polyKey\n\t*polyKey = [32]byte{}",
			},
			{
				File: "chacha20poly1305_generic.go", Count: 2,
				Old: "s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], nonce)",
				New: "s := &c.stream\n\ts.Init(c.key[:], nonce)",
			},
			{
				File: "chacha20poly1305_generic.go", Count: 2,
				Old: "p := poly1305.New(&polyKey)",
				New: "p := &c.mac\n\tp.Init(polyKey)",
			},
		},
		Threads: []thread{{Funcs: []string{"writeWithPadding", "writeUint64"}, Param: "c *chacha20poly1305"}},
		Hoists: []hoist{
			{Func: "writeWithPadding", Via: "c", Type: "chacha20poly1305", Vars: []string{"buf:pad"}},
			{Func: "writeUint64", Via: "c", Type: "chacha20poly1305", Vars: []string{"buf:u64"}},
		},
	},

	// Test support, ported to internal/lcryptotest for lcrypto's own tests.
	{Src: "go:internal/testhash", Dst: "testhash", Kit: true},
	{
		Src: "go:crypto/internal/cryptotest", Dst: "cryptotest", Kit: true,
		// Backend selection, FIPS module versions and cipher modes lcrypto lacks.
		DropFiles: []string{"implementations.go", "fips140.go", "blockmode.go", "*_wycheproof_test.go"},
		Patches: []patch{
			{
				File: "hash.go", Decl: "TestHash",
				Old: `if boring.Enabled || fips140.Version() == "v1.0.0" {`,
				New: "if _, ok := mh().(hash.Cloner); !ok { // lcrypto digests do not allocate clones.",
			},
			{
				File: "methods.go", Decl: "NoExtraMethods",
				Old: "t.Helper()\n",
				New: "t.Helper()\n\ttestenv.SkipIfTinyGo(t, \"NoExtraMethods needs reflect.Type.Method\")\n",
			},
			{
				File: "allocations.go", Decl: "SkipTestAllocations",
				Old: "if race.Enabled || msan.Enabled || asan.Enabled {",
				New: "if testenv.SanitizersEnabled {",
			},
		},
	},
	{
		Src: "go:crypto/internal/cryptotest/wycheproof", Dst: "wycheproof", Kit: true,
		Patches: []patch{{
			// Vectors are vendored rather than fetched.
			File: "wycheproof.go", Decl: "LoadVectorFile",
			Old: "dir := *wycheproofDir\n\tif dir == \"\" {\n\t\tdir = cryptotest.FetchModule(\n\t\t\tt, \"github.com/c2sp/wycheproof\", wycheproofVersion)\n\t}\n\n\tcontent, err := os.ReadFile(path.Join(dir, \"testvectors_v1\", filename))\n\tif err != nil {\n\t\tt.Fatalf(\"missing Wycheproof vector file %q: %v\", filename, err)\n\t}\n\n\terr = json.Unmarshal",
			New: "var content []byte\n\tif dir := *wycheproofDir; dir != \"\" {\n\t\tvar err error\n\t\tif content, err = os.ReadFile(path.Join(dir, \"testvectors_v1\", filename)); err != nil {\n\t\t\tt.Fatalf(\"missing Wycheproof vector file %q: %v\", filename, err)\n\t\t}\n\t} else {\n\t\tcontent = cryptotest.Vectors(t, \"wycheproof\", filename)\n\t}\n\n\terr := json.Unmarshal",
		}, {
			File: "wycheproof.go", Decl: "LoadVectorFile",
			Old: "so we fetch the module at runtime and read the\n\t// vector JSON from that module clone.",
			New: "so lcryptogen vendors the\n\t// vector files tests use into internal/lcryptotest/testdata.",
		}},
	},
	{Src: "go:crypto/internal/cryptotest/x509limbo", Dst: "x509limbo", Kit: true},
}

// ghashIterator is the upstream range-over-func block iterator of ghash and its loop header.
const ghashIterator = `blockIterator := func(yield func([]byte) bool) {
		for _, input := range inputs {
			for len(input) >= 16 {
				if !yield(input[:16]) {
					return
				}
				input = input[16:]
			}
			if len(input) > 0 {
				var partialBlock [gcmBlockSize]byte
				copy(partialBlock[:], input)
				if !yield(partialBlock[:]) {
					return
				}
			}
		}
	}

	// Compute the GHASH of the inputs by iterating over 16-byte blocks of the
	// inputs, XORing each block into the current state, and multiplying the
	// result by the key.
	for block := range blockIterator {`

// keccakPrologue is the upstream byte order handling at the top of keccakF1600Generic.
const keccakPrologue = `var a *[25]uint64
	if cpu.BigEndian {
		a = new([25]uint64)
		for i := range a {
			a[i] = byteorder.LEUint64(da[i*8:])
		}
		defer func() {
			for i := range a {
				byteorder.LEPutUint64(da[i*8:], a[i])
			}
		}()
	} else {
		a = (*[25]uint64)(unsafe.Pointer(da))
	}`

// montgomeryMulSpecialized are the fixed size cases of bigmod.Nat.montgomeryMul.
const montgomeryMulSpecialized = `	// The following specialized cases follow the exact same algorithm, but
	// optimized for the sizes most used in RSA. addMulVVW is implemented in
	// assembly with loop unrolling depending on the architecture and bounds
	// checks are removed by the compiler thanks to the constant size.
	case 1024 / _W:
		const n = 1024 / _W // compiler hint
		T := make([]uint, n*2)
		var c uint
		for i := 0; i < n; i++ {
			d := bLimbs[i]
			c1 := addMulVVW1024(&T[i], &aLimbs[0], d)
			Y := T[i] * m.m0inv
			c2 := addMulVVW1024(&T[i], &mLimbs[0], Y)
			T[n+i], c = bits.Add(c1, c2, c)
		}
		copy(x.reset(n).limbs, T[n:])
		x.maybeSubtractModulus(choice(c), m)

	case 1536 / _W:
		const n = 1536 / _W // compiler hint
		T := make([]uint, n*2)
		var c uint
		for i := 0; i < n; i++ {
			d := bLimbs[i]
			c1 := addMulVVW1536(&T[i], &aLimbs[0], d)
			Y := T[i] * m.m0inv
			c2 := addMulVVW1536(&T[i], &mLimbs[0], Y)
			T[n+i], c = bits.Add(c1, c2, c)
		}
		copy(x.reset(n).limbs, T[n:])
		x.maybeSubtractModulus(choice(c), m)

	case 2048 / _W:
		const n = 2048 / _W // compiler hint
		T := make([]uint, n*2)
		var c uint
		for i := 0; i < n; i++ {
			d := bLimbs[i]
			c1 := addMulVVW2048(&T[i], &aLimbs[0], d)
			Y := T[i] * m.m0inv
			c2 := addMulVVW2048(&T[i], &mLimbs[0], Y)
			T[n+i], c = bits.Add(c1, c2, c)
		}
		copy(x.reset(n).limbs, T[n:])
		x.maybeSubtractModulus(choice(c), m)
`

// mulSpecialized are the fixed size cases of bigmod.Nat.Mul.
const mulSpecialized = `	case 1024 / _W:
		const n = 1024 / _W // compiler hint
		T := make([]uint, n*2)
		for i := 0; i < n; i++ {
			T[n+i] = addMulVVW1024(&T[i], &xLimbs[0], yLimbs[i])
		}
		return x.Mod(&Nat{limbs: T}, m)
	case 1536 / _W:
		const n = 1536 / _W // compiler hint
		T := make([]uint, n*2)
		for i := 0; i < n; i++ {
			T[n+i] = addMulVVW1536(&T[i], &xLimbs[0], yLimbs[i])
		}
		return x.Mod(&Nat{limbs: T}, m)
	case 2048 / _W:
		const n = 2048 / _W // compiler hint
		T := make([]uint, n*2)
		for i := 0; i < n; i++ {
			T[n+i] = addMulVVW2048(&T[i], &xLimbs[0], yLimbs[i])
		}
		return x.Mod(&Nat{limbs: T}, m)
`

// lazyCurveB patches the lazily computed curve constant b of nistec's curve
// file into one computed at init, without sync.Once. tail ends its bytes.
func lazyCurveB(curve, tail string) []patch {
	elem := "fiat." + strings.ToUpper(curve[:1]) + curve[1:] + "Element"
	return []patch{
		{
			File: curve + ".go",
			Old: "var _" + curve + "B *" + elem + "\nvar _" + curve + "BOnce sync.Once\n\nfunc " + curve + "B() *" + elem +
				" {\n\t_" + curve + "BOnce.Do(func() {\n\t\t_" + curve + "B, _ = new(" + elem + ").SetBytes([]byte{",
			New: "var _" + curve + "B " + elem + "\n\nfunc init() {\n\tb := [...]byte{",
		},
		{
			File: curve + ".go",
			Old:  tail + "})\n\t})\n\treturn _" + curve + "B\n}",
			New:  tail + "}\n\t_" + curve + "B.SetBytes(b[:])\n}\n\nfunc " + curve + "B() *" + elem + " { return &_" + curve + "B }",
		},
	}
}
