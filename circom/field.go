// Package circom implements an arithmetic ZKBoo proof system for Circom R1CS circuits.
// It extends ZKBoo from boolean circuits to arithmetic circuits over the BN254 scalar field,
// enabling any Circom-compiled circuit to be proven using the MPC-in-the-head paradigm.
package circom

import (
	"crypto/rand"
	"math/big"
)

// BN254 scalar field prime: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
var fieldPrime *big.Int

func init() {
	fieldPrime = new(big.Int)
	fieldPrime.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
}

// FieldSize is the size of a field element in bytes.
const FieldSize = 32

// FieldElement represents an element of the BN254 scalar field.
// Internally stored as a *big.Int in [0, p).
type FieldElement struct {
	v *big.Int
}

// NewFieldElement creates a new field element from a big.Int, reducing mod p.
func NewFieldElement(x *big.Int) FieldElement {
	v := new(big.Int).Mod(x, fieldPrime)
	return FieldElement{v: v}
}

// Zero returns the additive identity.
func Zero() FieldElement {
	return FieldElement{v: new(big.Int)}
}

// One returns the multiplicative identity.
func One() FieldElement {
	return FieldElement{v: big.NewInt(1)}
}

// RandomFieldElement generates a cryptographically random field element.
func RandomFieldElement() (FieldElement, error) {
	max := new(big.Int).Sub(fieldPrime, big.NewInt(1))
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return FieldElement{}, err
	}
	return FieldElement{v: v}, nil
}

// FieldElementFromBytes creates a field element from little-endian bytes.
func FieldElementFromBytes(b []byte) FieldElement {
	// Reverse to big-endian for big.Int
	rev := make([]byte, len(b))
	for i := range b {
		rev[len(b)-1-i] = b[i]
	}
	v := new(big.Int).SetBytes(rev)
	v.Mod(v, fieldPrime)
	return FieldElement{v: v}
}

// Bytes returns the field element as 32 little-endian bytes.
func (f FieldElement) Bytes() [FieldSize]byte {
	var out [FieldSize]byte
	b := f.v.Bytes() // big-endian
	// Copy into out in little-endian order
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// BigInt returns the underlying big.Int value.
func (f FieldElement) BigInt() *big.Int {
	return new(big.Int).Set(f.v)
}

// Add returns f + g mod p.
func (f FieldElement) Add(g FieldElement) FieldElement {
	v := new(big.Int).Add(f.v, g.v)
	v.Mod(v, fieldPrime)
	return FieldElement{v: v}
}

// Sub returns f - g mod p.
func (f FieldElement) Sub(g FieldElement) FieldElement {
	v := new(big.Int).Sub(f.v, g.v)
	v.Mod(v, fieldPrime)
	return FieldElement{v: v}
}

// Mul returns f * g mod p.
func (f FieldElement) Mul(g FieldElement) FieldElement {
	v := new(big.Int).Mul(f.v, g.v)
	v.Mod(v, fieldPrime)
	return FieldElement{v: v}
}

// Neg returns -f mod p.
func (f FieldElement) Neg() FieldElement {
	if f.v.Sign() == 0 {
		return Zero()
	}
	v := new(big.Int).Sub(fieldPrime, f.v)
	return FieldElement{v: v}
}

// Equal returns true if f == g.
func (f FieldElement) Equal(g FieldElement) bool {
	return f.v.Cmp(g.v) == 0
}

// IsZero returns true if f == 0.
func (f FieldElement) IsZero() bool {
	return f.v.Sign() == 0
}

// String returns the decimal representation.
func (f FieldElement) String() string {
	return f.v.String()
}

// FieldPrime returns the field modulus.
func FieldPrime() *big.Int {
	return new(big.Int).Set(fieldPrime)
}
