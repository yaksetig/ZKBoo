package zkboo

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
)

// Proof holds the A and Z data for a proof.
type Proof struct {
	A []byte `json:"A"`
	Z []byte `json:"Z"`
}

// ProveSHA1 generates a proof for the given message using SHA-1.
// It returns a Proof containing the hash as A and a placeholder Z.
func ProveSHA1(msg []byte) (*Proof, error) {
	h := sha1.Sum(msg)
	return &Proof{A: h[:], Z: []byte{}}, nil
}

// ProveSHA256 generates a proof for the given message using SHA-256.
// It returns a Proof containing the hash as A and a placeholder Z.
func ProveSHA256(msg []byte) (*Proof, error) {
	h := sha256.Sum256(msg)
	return &Proof{A: h[:], Z: []byte{}}, nil
}

// VerifySHA1 checks that the proof matches the given message using SHA-1.
func VerifySHA1(msg []byte, p *Proof) bool {
	h := sha1.Sum(msg)
	return bytes.Equal(p.A, h[:])
}

// VerifySHA256 checks that the proof matches the given message using SHA-256.
func VerifySHA256(msg []byte, p *Proof) bool {
	h := sha256.Sum256(msg)
	return bytes.Equal(p.A, h[:])
}
