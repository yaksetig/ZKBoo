package zkboo

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
)

type ProofSHA1 struct {
	Digest [20]byte
}

type ProofSHA256 struct {
	Digest [32]byte
}

func ProveSHA1(msg []byte) ProofSHA1 {
	h := sha1.Sum(msg)
	return ProofSHA1{Digest: h}
}

func verifySHA1(msg []byte, proof ProofSHA1) (bool, [20]byte) {
	h := sha1.Sum(msg)
	return bytes.Equal(h[:], proof.Digest[:]), h
}

func ProveSHA256(msg []byte) ProofSHA256 {
	h := sha256.Sum256(msg)
	return ProofSHA256{Digest: h}
}

func verifySHA256(msg []byte, proof ProofSHA256) (bool, [32]byte) {
	h := sha256.Sum256(msg)
	return bytes.Equal(h[:], proof.Digest[:]), h
}
